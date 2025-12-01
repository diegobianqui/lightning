#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/pipecmd/pipecmd.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/str/str.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <errno.h>
#include <inttypes.h>
#include <plugins/libplugin.h>

#define RPC_TRANSACTION_ALREADY_IN_CHAIN -27

struct bitcoind {
	/* eg. "bitcoin-cli" */
	char *cli;

	/* -datadir arg for bitcoin-cli. */
	char *datadir;

	/* bitcoind's version, used for compatibility checks. */
	u32 version;

	/* Is bitcoind synced?  If not, we retry. */
	bool synced;

	/* Passthrough parameters for bitcoin-cli */
	char *rpcuser, *rpcpass, *rpcconnect, *rpcport;
	u64 rpcclienttimeout;

	/* Whether we fake fees (regtest) */
	bool fake_fees;

	/* Override in case we're developer mode for testing*/
	bool dev_no_fake_fees;

	/* Override initialblockdownload (using canned blocks sets this) */
	bool dev_ignore_ibd;
};

static struct bitcoind *bitcoind;

struct bitcoin_cli {
	const char **args;
	const char **stdinargs;
	char *output;
	size_t output_bytes;
	int exitstatus;
	struct command *cmd;
	/* Used to stash content between multiple calls */
	void *stash;
};

/* Add the n'th arg to *args, incrementing n and keeping args of size n+1 */
static void add_arg(const char ***args, const char *arg TAKES)
{
	if (taken(arg))
		tal_steal(*args, arg);
	tal_arr_expand(args, arg);
}

/* If stdinargs is non-NULL, that is where we put additional args */
static const char **gather_argsv(const tal_t *ctx, const char ***stdinargs, const char *cmd, va_list ap)
{
	const char **args = tal_arr(ctx, const char *, 1);
	const char *arg;

	args[0] = bitcoind->cli ? bitcoind->cli : chainparams->cli;
	if (chainparams->cli_args)
		add_arg(&args, chainparams->cli_args);
	if (bitcoind->datadir)
		add_arg(&args, tal_fmt(args, "-datadir=%s", bitcoind->datadir));
	if (bitcoind->rpcclienttimeout) {
		/* Use the maximum value of rpcclienttimeout and retry_timeout to avoid
		   the bitcoind backend hanging for too long. */
		if (bitcoind->retry_timeout &&
		    bitcoind->retry_timeout > bitcoind->rpcclienttimeout)
			bitcoind->rpcclienttimeout = bitcoind->retry_timeout;

		add_arg(&args,
			tal_fmt(args, "-rpcclienttimeout=%"PRIu64, bitcoind->rpcclienttimeout));
	}
	if (bitcoind->rpcconnect)
		add_arg(&args,
			tal_fmt(args, "-rpcconnect=%s", bitcoind->rpcconnect));
	if (bitcoind->rpcport)
		add_arg(&args,
			tal_fmt(args, "-rpcport=%s", bitcoind->rpcport));
	if (bitcoind->rpcuser)
		add_arg(&args, tal_fmt(args, "-rpcuser=%s", bitcoind->rpcuser));
	if (bitcoind->rpcpass)
		// Always pipe the rpcpassword via stdin. Do not pass it using an
		// `-rpcpassword` argument - secrets in arguments can leak when listing
		// system processes.
		add_arg(&args, "-stdinrpcpass");
	/* To avoid giant command lines, we use -stdin (avail since bitcoin 0.13) */
	if (stdinargs)
		add_arg(&args, "-stdin");

	add_arg(&args, cmd);
	while ((arg = va_arg(ap, char *)) != NULL) {
		if (stdinargs)
			add_arg(stdinargs, arg);
		else
			add_arg(&args, arg);
	}
	add_arg(&args, NULL);

	return args;
}

static LAST_ARG_NULL const char **
gather_args(const tal_t *ctx, const char ***stdinargs, const char *cmd, ...)
{
	va_list ap;
	const char **ret;

	va_start(ap, cmd);
	ret = gather_argsv(ctx, stdinargs, cmd, ap);
	va_end(ap);

	return ret;
}

/* Execute bitcoin-cli command synchronously and return output */
static struct bitcoin_cli *run_bitcoin_cli(const tal_t *ctx,
					   struct command *cmd,
					   const char **args,
					   const char **stdinargs)
{
	struct bitcoin_cli *bcli = tal(ctx, struct bitcoin_cli);
	int in, from;
	pid_t pid;
	int status;
	int ret;
	char *buf;
	size_t len;

	bcli->args = args;
	bcli->stdinargs = stdinargs;
	bcli->cmd = cmd;
	bcli->output = NULL;
	bcli->output_bytes = 0;
	bcli->exitstatus = 0;

	pid = pipecmdarr(&in, &from, &from,
			 cast_const2(char **, args));
	if (pid < 0)
		plugin_err(cmd->plugin, "%s exec failed: %s",
			   args[0], strerror(errno));

	if (bitcoind->rpcpass) {
		if (!write_all(in, bitcoind->rpcpass,
			       strlen(bitcoind->rpcpass)))
			plugin_err(cmd->plugin, "write rpcpass failed: %s",
				   strerror(errno));
		if (!write_all(in, "\n", 1))
			plugin_err(cmd->plugin, "write newline failed: %s",
				   strerror(errno));
	}

	for (size_t i = 0; i < tal_count(stdinargs); i++) {
		if (!write_all(in, stdinargs[i], strlen(stdinargs[i])))
			plugin_err(cmd->plugin,
				   "write stdin arg failed: %s",
				   strerror(errno));
		if (!write_all(in, "\n", 1))
			plugin_err(cmd->plugin, "write newline failed: %s",
				   strerror(errno));
	}
	close(in);

	buf = grab_fd_str(bcli, from);
	if (!buf)
		plugin_err(cmd->plugin, "grab_fd_str failed");

	while ((ret = waitpid(pid, &status, 0)) < 0 && errno == EINTR)
		;
	if (ret != pid)
		plugin_err(cmd->plugin, "%s waitpid: %s", args[0],
			   ret == 0 ? "not exited?" : strerror(errno));

	if (!WIFEXITED(status))
		plugin_err(cmd->plugin, "%s died with signal %i",
			   args[0], WTERMSIG(status));

	bcli->exitstatus = WEXITSTATUS(status);
	bcli->output = buf;
	bcli->output_bytes = strlen(buf);

	return bcli;
}

/* For printing: simple string of args (no secrets!) */
static char *args_string(const tal_t *ctx, const char **args,
			 const char **stdinargs)
{
	size_t i;
	char *ret = tal_strdup(ctx, args[0]);

	for (i = 1; args[i]; i++) {
		ret = tal_strcat(ctx, take(ret), " ");
		if (strstarts(args[i], "-rpcpassword")) {
			ret = tal_strcat(ctx, take(ret), "-rpcpassword=...");
		} else if (strstarts(args[i], "-rpcuser")) {
			ret = tal_strcat(ctx, take(ret), "-rpcuser=...");
		} else {
			ret = tal_strcat(ctx, take(ret), args[i]);
		}
	}
	for (i = 0; i < tal_count(stdinargs); i++) {
		ret = tal_strcat(ctx, take(ret), " ");
		ret = tal_strcat(ctx, take(ret), stdinargs[i]);
	}
	return ret;
}

/* Synchronous wrapper to execute bitcoin-cli and process result */
static struct command_result *run_bcli(struct command *cmd,
				       struct command_result *
				       (*process)(struct bitcoin_cli *),
				       bool nonzero_exit_ok,
				       const char *method,
				       va_list ap)
{
	const char **stdinargs = tal_arr(cmd, const char *, 0);
	const char **args = gather_argsv(cmd, &stdinargs, method, ap);
	struct bitcoin_cli *bcli;
	struct command_result *res;

	bcli = run_bitcoin_cli(cmd, cmd, args, stdinargs);

	if (!nonzero_exit_ok && bcli->exitstatus != 0) {
		char *err_str = tal_strndup(cmd, bcli->output,
					    bcli->output_bytes);
		return command_done_err(cmd, BCLI_ERROR, err_str, NULL);
	}

	res = process(bcli);
	tal_free(bcli);

	return res;
}

static void strip_trailing_whitespace(char *str, size_t len)
{
	size_t stripped_len = len;
	while (stripped_len > 0 && cisspace(str[stripped_len-1]))
		stripped_len--;

	str[stripped_len] = 0x00;
}

static struct command_result *command_err_bcli_badjson(struct bitcoin_cli *bcli,
						       const char *errmsg)
{
	char *args_str = args_string(bcli->cmd, bcli->args, bcli->stdinargs);
	char *err = tal_fmt(bcli, "%s: bad JSON: %s (%.*s)",
			    args_str, errmsg,
			    (int)bcli->output_bytes, bcli->output);
	return command_done_err(bcli->cmd, BCLI_ERROR, err, NULL);
}

/* Don't use this in general: it's better to omit fields. */
static void json_add_null(struct json_stream *stream, const char *fieldname)
{
	json_add_primitive(stream, fieldname, "null");
}

static struct command_result *process_getutxout(struct bitcoin_cli *bcli)
{
	const jsmntok_t *tokens;
	struct json_stream *response;
	struct bitcoin_tx_output output;
	const char *err;

	/* As of at least v0.15.1.0, bitcoind returns "success" but an empty
	   string on a spent txout. */
	if (bcli->exitstatus != 0 || bcli->output_bytes == 0) {
		response = jsonrpc_stream_success(bcli->cmd);
		json_add_null(response, "amount");
		json_add_null(response, "script");

		return command_finished(bcli->cmd, response);
	}

	tokens = json_parse_simple(bcli->output, bcli->output,
				   bcli->output_bytes);
	if (!tokens) {
		return command_err_bcli_badjson(bcli, "cannot parse");
	}

	err = json_scan(tmpctx, bcli->output, tokens,
		       "{value:%,scriptPubKey:{hex:%}}",
		       JSON_SCAN(json_to_bitcoin_amount,
				 &output.amount.satoshis), /* Raw: bitcoind */
		       JSON_SCAN_TAL(bcli, json_tok_bin_from_hex,
				     &output.script));
	if (err)
		return command_err_bcli_badjson(bcli, err);

	response = jsonrpc_stream_success(bcli->cmd);
	json_add_sats(response, "amount", output.amount);
	json_add_string(response, "script", tal_hex(response, output.script));

	return command_finished(bcli->cmd, response);
}

static struct command_result *process_getblockchaininfo(struct bitcoin_cli *bcli)
{
	const jsmntok_t *tokens;
	struct json_stream *response;
	bool ibd;
	u32 headers, blocks;
	const char *chain, *err;

	tokens = json_parse_simple(bcli->output,
				   bcli->output, bcli->output_bytes);
	if (!tokens) {
		return command_err_bcli_badjson(bcli, "cannot parse");
	}

	err = json_scan(tmpctx, bcli->output, tokens,
			"{chain:%,headers:%,blocks:%,initialblockdownload:%}",
			JSON_SCAN_TAL(tmpctx, json_strdup, &chain),
			JSON_SCAN(json_to_number, &headers),
			JSON_SCAN(json_to_number, &blocks),
			JSON_SCAN(json_to_bool, &ibd));
	if (err)
		return command_err_bcli_badjson(bcli, err);

	if (bitcoind->dev_ignore_ibd)
		ibd = false;

	response = jsonrpc_stream_success(bcli->cmd);
	json_add_string(response, "chain", chain);
	json_add_u32(response, "headercount", headers);
	json_add_u32(response, "blockcount", blocks);
	json_add_bool(response, "ibd", ibd);

	return command_finished(bcli->cmd, response);
}

struct estimatefee_params {
	u32 blocks;
	const char *style;
};

static const struct estimatefee_params estimatefee_params[] = {
	{ 2, "CONSERVATIVE" },
	{ 6, "ECONOMICAL" },
	{ 12, "ECONOMICAL" },
	{ 100, "ECONOMICAL" },
};

struct estimatefees_stash {
	/* This is max(mempoolminfee,minrelaytxfee) */
	u64 perkb_floor;
	u32 cursor;
	/* FIXME: We use u64 but lightningd will store them as u32. */
	u64 perkb[ARRAY_SIZE(estimatefee_params)];
};

static struct command_result *
estimatefees_null_response(struct bitcoin_cli *bcli)
{
	struct json_stream *response = jsonrpc_stream_success(bcli->cmd);

	/* We give a floor, which is the standard minimum */
	json_array_start(response, "feerates");
	json_array_end(response);
	json_add_u32(response, "feerate_floor", 1000);

	return command_finished(bcli->cmd, response);
}

static struct command_result *
estimatefees_null_response_cmd(struct command *cmd)
{
	struct json_stream *response = jsonrpc_stream_success(cmd);

	/* We give a floor, which is the standard minimum */
	json_array_start(response, "feerates");
	json_array_end(response);
	json_add_u32(response, "feerate_floor", 1000);

	return command_finished(cmd, response);
}

static struct command_result *
estimatefees_parse_feerate(struct bitcoin_cli *bcli, u64 *feerate)
{
	const jsmntok_t *tokens;

	tokens = json_parse_simple(bcli->output,
				   bcli->output, bcli->output_bytes);
	if (!tokens) {
		return command_err_bcli_badjson(bcli, "cannot parse");
	}

	if (json_scan(tmpctx, bcli->output, tokens, "{feerate:%}",
		      JSON_SCAN(json_to_bitcoin_amount, feerate)) != NULL) {
		/* Paranoia: if it had a feerate, but was malformed: */
		if (json_get_member(bcli->output, tokens, "feerate"))
			return command_err_bcli_badjson(bcli, "cannot scan");
		/* Regtest fee estimation is generally awful: Fake it at min. */
		if (bitcoind->fake_fees) {
			*feerate = 1000;
			return NULL;
		}
		/* We return null if estimation failed, and bitcoin-cli will
		 * exit with 0 but no feerate field on failure. */
		return estimatefees_null_response(bcli);
	}

	return NULL;
}

static struct command_result *process_sendrawtransaction(struct bitcoin_cli *bcli)
{
	struct json_stream *response;

	/* This is useful for functional tests. */
	if (bcli->exitstatus != 0)
		plugin_log(bcli->cmd->plugin, LOG_DBG,
			   "sendrawtx exit %i: %.*s",
			   bcli->exitstatus,
			   (u32)bcli->output_bytes-1,
			   bcli->output);

	response = jsonrpc_stream_success(bcli->cmd);
	json_add_bool(response, "success",
		      bcli->exitstatus == 0 ||
		      bcli->exitstatus == RPC_TRANSACTION_ALREADY_IN_CHAIN);
	json_add_string(response, "errmsg",
			bcli->exitstatus ?
			tal_strndup(bcli->cmd,
				    bcli->output, bcli->output_bytes-1)
			: "");

	return command_finished(bcli->cmd, response);
}

struct getrawblock_stash {
	const char *block_hash;
	u32 block_height;
	const char *block_hex;
	int *peers;
};

static struct command_result *process_rawblock(struct bitcoin_cli *bcli)
{
	struct json_stream *response;
	struct getrawblock_stash *stash = bcli->stash;

	strip_trailing_whitespace(bcli->output, bcli->output_bytes);
	stash->block_hex = tal_steal(stash, bcli->output);

	response = jsonrpc_stream_success(bcli->cmd);
	json_add_string(response, "blockhash", stash->block_hash);
	json_add_string(response, "block", stash->block_hex);

	return command_finished(bcli->cmd, response);
}

static struct command_result *
getrawblockbyheight_notfound(struct command *cmd)
{
	struct json_stream *response;

	response = jsonrpc_stream_success(cmd);
	json_add_null(response, "blockhash");
	json_add_null(response, "block");

	return command_finished(cmd, response);
}

/* Get a raw block given its height.
 * Calls `getblockhash` then `getblock` to retrieve it from bitcoin-cli.
 * Will return early with null fields if block isn't known (yet).
 */
static struct command_result *getrawblockbyheight(struct command *cmd,
                                                  const char *buf,
                                                  const jsmntok_t *toks)
{
	struct getrawblock_stash *stash;
	u32 *height;
	const char **args, **stdinargs;
	struct bitcoin_cli *bcli_hash, *bcli_block;
	const jsmntok_t *tokens;

	/* bitcoin-cli wants a string. */
	if (!param(cmd, buf, toks,
	           p_req("height", param_number, &height),
	           NULL))
		return command_param_failed();

	stash = tal(cmd, struct getrawblock_stash);
	stash->block_height = *height;
	stash->peers = NULL;

	/* Call getblockhash */
	stdinargs = tal_arr(cmd, const char *, 0);
	args = gather_args(cmd, &stdinargs, "getblockhash",
			   take(tal_fmt(NULL, "%u", stash->block_height)),
			   NULL);
	bcli_hash = run_bitcoin_cli(cmd, cmd, args, stdinargs);

	if (bcli_hash->exitstatus != 0) {
		if (bcli_hash->exitstatus == 8) {
			tal_free(bcli_hash);
			return getrawblockbyheight_notfound(cmd);
		}
		return command_done_err(cmd, BCLI_ERROR,
					tal_strdup(cmd, bcli_hash->output),
					NULL);
	}

	strip_trailing_whitespace(bcli_hash->output,
				  bcli_hash->output_bytes);
	stash->block_hash = tal_strdup(stash, bcli_hash->output);
	if (!stash->block_hash || strlen(stash->block_hash) != 64) {
		tal_free(bcli_hash);
		return command_done_err(cmd, BCLI_ERROR,
					"bad blockhash", NULL);
	}
	tal_free(bcli_hash);

	/* Call getblock */
	stdinargs = tal_arr(cmd, const char *, 0);
	args = gather_args(cmd, &stdinargs, "getblock",
			   stash->block_hash, "0", NULL);
	bcli_block = run_bitcoin_cli(cmd, cmd, args, stdinargs);

	if (bcli_block->exitstatus != 0) {
		tal_free(bcli_block);
		return getrawblockbyheight_notfound(cmd);
	}

	bcli_block->stash = stash;
	struct command_result *res = process_rawblock(bcli_block);
	tal_free(bcli_block);
	return res;
}

/* Get infos about the block chain.
 * Calls `getblockchaininfo` and returns headers count, blocks count,
 * the chain id, and whether this is initialblockdownload.
 */
static struct command_result *getchaininfo(struct command *cmd,
                                           const char *buf UNUSED,
                                           const jsmntok_t *toks UNUSED)
{
	u32 *height UNUSED;
	const char **args, **stdinargs;
	struct bitcoin_cli *bcli;

	if (!param(cmd, buf, toks,
		   p_opt("last_height", param_number, &height),
		   NULL))
		return command_param_failed();

	stdinargs = tal_arr(cmd, const char *, 0);
	args = gather_args(cmd, &stdinargs, "getblockchaininfo", NULL);
	bcli = run_bitcoin_cli(cmd, cmd, args, stdinargs);

	if (bcli->exitstatus != 0)
		return command_done_err(cmd, BCLI_ERROR,
					tal_strdup(cmd, bcli->output),
					NULL);

	struct command_result *res = process_getblockchaininfo(bcli);
	tal_free(bcli);
	return res;
}

/* Add a feerate, but don't publish one that bitcoind won't accept. */
static void json_add_feerate(struct json_stream *result, const char *fieldname,
			     struct command *cmd,
			     const struct estimatefees_stash *stash,
			     uint64_t value)
{
	/* Anthony Towns reported signet had a 900kbtc fee block, and then
	 * CLN got upset scanning feerate.  It expects a u32. */
	if (value > 0xFFFFFFFF) {
		plugin_log(cmd->plugin, LOG_UNUSUAL,
			   "Feerate %"PRIu64" is ridiculous: "
			   "trimming to 32 bites",
			   value);
		value = 0xFFFFFFFF;
	}
	/* 0 is special, it means "unknown" */
	if (value && value < stash->perkb_floor) {
		plugin_log(cmd->plugin, LOG_DBG,
			   "Feerate %s raised from %"PRIu64
			   " perkb to floor of %"PRIu64,
			   fieldname, value, stash->perkb_floor);
		json_add_u64(result, fieldname, stash->perkb_floor);
	} else {
		json_add_u64(result, fieldname, value);
	}
}

static struct command_result *getminfees_done(struct bitcoin_cli *bcli)
{
	const jsmntok_t *tokens;
	const char *err;
	u64 mempoolfee, relayfee;
	struct estimatefees_stash *stash = bcli->stash;

	if (bcli->exitstatus != 0)
		return estimatefees_null_response(bcli);

	tokens = json_parse_simple(bcli->output,
				   bcli->output, bcli->output_bytes);
	if (!tokens)
		return command_err_bcli_badjson(bcli,
						"cannot parse getmempoolinfo");

	/* Look at minrelaytxfee they configured, and current min fee to get
	 * into mempool. */
	err = json_scan(tmpctx, bcli->output, tokens,
			"{mempoolminfee:%,minrelaytxfee:%}",
			JSON_SCAN(json_to_bitcoin_amount, &mempoolfee),
			JSON_SCAN(json_to_bitcoin_amount, &relayfee));
	if (err)
		return command_err_bcli_badjson(bcli, err);

	stash->perkb_floor = max_u64(mempoolfee, relayfee);
	return NULL;
}

static struct command_result *estimatefees_done(struct bitcoin_cli *bcli)
{
	struct command_result *err;
	struct estimatefees_stash *stash = bcli->stash;

	/* If we cannot estimate fees, no need to continue bothering bitcoind. */
	if (bcli->exitstatus != 0)
		return estimatefees_null_response(bcli);

	err = estimatefees_parse_feerate(bcli, &stash->perkb[stash->cursor]);
	if (err)
		return err;

	return NULL;
}

/* Get the current feerates. We use an urgent feerate for unilateral_close
 * and max, a slightly less urgent feerate for htlc_resolution and penalty
 * transactions, a slow feerate for min, and a normal one for all others.
 */
static struct command_result *estimatefees(struct command *cmd,
					   const char *buf UNUSED,
					   const jsmntok_t *toks UNUSED)
{
	struct estimatefees_stash *stash = tal(cmd, struct estimatefees_stash);
	const char **args, **stdinargs;
	struct bitcoin_cli *bcli;
	struct json_stream *response;
	struct command_result *res;

	if (!param(cmd, buf, toks, NULL))
		return command_param_failed();

	/* Get mempoolinfo */
	stdinargs = tal_arr(cmd, const char *, 0);
	args = gather_args(cmd, &stdinargs, "getmempoolinfo", NULL);
	bcli = run_bitcoin_cli(cmd, cmd, args, stdinargs);

	if (bcli->exitstatus != 0) {
		tal_free(bcli);
		return estimatefees_null_response_cmd(cmd);
	}

	bcli->stash = stash;
	res = getminfees_done(bcli);
	if (res) {
		tal_free(bcli);
		return res;
	}
	tal_free(bcli);

	/* Get all fee estimates */
	for (size_t i = 0; i < ARRAY_SIZE(stash->perkb); i++) {
		stash->cursor = i;
		stdinargs = tal_arr(cmd, const char *, 0);
		args = gather_args(cmd, &stdinargs, "estimatesmartfee",
				   take(tal_fmt(NULL, "%u",
					     estimatefee_params[i].blocks)),
				   estimatefee_params[i].style,
				   NULL);
		bcli = run_bitcoin_cli(cmd, cmd, args, stdinargs);

		if (bcli->exitstatus == 0) {
			bcli->stash = stash;
			res = estimatefees_done(bcli);
			if (res) {
				tal_free(bcli);
				return res;
			}
		}
		tal_free(bcli);
	}

	/* Build response */
	response = jsonrpc_stream_success(cmd);
	json_array_start(response, "feerates");
	for (size_t i = 0; i < ARRAY_SIZE(stash->perkb); i++) {
		if (!stash->perkb[i])
			continue;
		json_object_start(response, NULL);
		json_add_u32(response, "blocks", estimatefee_params[i].blocks);
		json_add_feerate(response, "feerate", cmd, stash,
				 stash->perkb[i]);
		json_object_end(response);
	}
	json_array_end(response);
	json_add_u64(response, "feerate_floor", stash->perkb_floor);
	return command_finished(cmd, response);
}

/* Send a transaction to the Bitcoin network.
 * Calls `sendrawtransaction` using the first parameter as the raw tx.
 */
static struct command_result *sendrawtransaction(struct command *cmd,
                                                 const char *buf,
                                                 const jsmntok_t *toks)
{
	const char *tx, *highfeesarg;
	bool *allowhighfees;
	const char **args, **stdinargs;
	struct bitcoin_cli *bcli;

	/* bitcoin-cli wants strings. */
	if (!param(cmd, buf, toks,
	           p_req("tx", param_string, &tx),
		   p_req("allowhighfees", param_bool, &allowhighfees),
	           NULL))
		return command_param_failed();

	if (*allowhighfees)
		highfeesarg = "0";
	else
		highfeesarg = NULL;

	stdinargs = tal_arr(cmd, const char *, 0);
	args = gather_args(cmd, &stdinargs, "sendrawtransaction",
			   tx, highfeesarg, NULL);
	bcli = run_bitcoin_cli(cmd, cmd, args, stdinargs);

	struct command_result *res = process_sendrawtransaction(bcli);
	tal_free(bcli);
	return res;
}

static struct command_result *getutxout(struct command *cmd,
                                       const char *buf,
                                       const jsmntok_t *toks)
{
	const char *txid, *vout;
	const char **args, **stdinargs;
	struct bitcoin_cli *bcli;

	/* bitcoin-cli wants strings. */
	if (!param(cmd, buf, toks,
	           p_req("txid", param_string, &txid),
	           p_req("vout", param_string, &vout),
	           NULL))
		return command_param_failed();

	stdinargs = tal_arr(cmd, const char *, 0);
	args = gather_args(cmd, &stdinargs, "gettxout", txid, vout, NULL);
	bcli = run_bitcoin_cli(cmd, cmd, args, stdinargs);

	struct command_result *res = process_getutxout(bcli);
	tal_free(bcli);
	return res;
}

static void bitcoind_failure(struct plugin *p, const char *error_message)
{
	const char **cmd = gather_args(bitcoind, NULL, "echo", NULL);
	plugin_err(p, "\n%s\n\n"
		      "Make sure you have bitcoind running and that bitcoin-cli"
		      " is able to connect to bitcoind.\n\n"
		      "You can verify that your Bitcoin Core installation is"
		      " ready for use by running:\n\n"
		      "    $ %s 'hello world'\n", error_message,
		   args_string(cmd, cmd, NULL));
}

/* Do some sanity checks on bitcoind based on the output of `getnetworkinfo`. */
static void parse_getnetworkinfo_result(struct plugin *p, const char *buf)
{
	const jsmntok_t *result;
	bool tx_relay;
	u32 min_version = 220000;
	const char *err;

	result = json_parse_simple(NULL, buf, strlen(buf));
	if (!result)
		plugin_err(p, "Invalid response to '%s': '%s'. Can not "
			      "continue without proceeding to sanity checks.",
			   args_string(tmpctx, gather_args(bitcoind, NULL, "getnetworkinfo", NULL), NULL),
			   buf);

	/* Check that we have a fully-featured `estimatesmartfee`. */
	err = json_scan(tmpctx, buf, result, "{version:%,localrelay:%}",
			JSON_SCAN(json_to_u32, &bitcoind->version),
			JSON_SCAN(json_to_bool, &tx_relay));
	if (err)
		plugin_err(p, "%s.  Got '%.*s'. Can not"
			   " continue without proceeding to sanity checks.",
			   err,
			   json_tok_full_len(result), json_tok_full(buf, result));

	if (bitcoind->version < min_version)
		plugin_err(p, "Unsupported bitcoind version %"PRIu32", at least"
			      " %"PRIu32" required.", bitcoind->version, min_version);

	/* We don't support 'blocksonly', as we rely on transaction relay for fee
	 * estimates. */
	if (!tx_relay)
		plugin_err(p, "The 'blocksonly' mode of bitcoind, or any option "
			      "deactivating transaction relay is not supported.");

	tal_free(result);
}

static void wait_and_check_bitcoind(struct plugin *p)
{
	int in, from, status;
	pid_t child;
	const char **cmd = gather_args(
	    bitcoind, NULL, "-rpcwait", "-rpcwaittimeout=30", "getnetworkinfo", NULL);
	char *output = NULL;

	child = pipecmdarr(&in, &from, &from, cast_const2(char **, cmd));

	if (bitcoind->rpcpass)
		write_all(in, bitcoind->rpcpass, strlen(bitcoind->rpcpass));

	close(in);

	if (child < 0) {
		if (errno == ENOENT)
			bitcoind_failure(
			    p,
			    "bitcoin-cli not found. Is bitcoin-cli "
			    "(part of Bitcoin Core) available in your PATH?");
		plugin_err(p, "%s exec failed: %s", cmd[0], strerror(errno));
	}

	output = grab_fd_str(cmd, from);

	waitpid(child, &status, 0);

	if (!WIFEXITED(status))
		bitcoind_failure(p, tal_fmt(bitcoind, "Death of %s: signal %i",
					    cmd[0], WTERMSIG(status)));

	if (WEXITSTATUS(status) != 0) {
		if (WEXITSTATUS(status) == 1)
			bitcoind_failure(p,
					 "RPC connection timed out. Could "
					 "not connect to bitcoind using "
					 "bitcoin-cli. Is bitcoind running?");
		bitcoind_failure(p,
				 tal_fmt(bitcoind, "%s exited with code %i: %s",
					 cmd[0], WEXITSTATUS(status), output));
	}

	parse_getnetworkinfo_result(p, output);

	tal_free(cmd);
}

static void memleak_mark_bitcoind(struct plugin *p, struct htable *memtable)
{
	memleak_scan_obj(memtable, bitcoind);
}

static const char *init(struct command *init_cmd, const char *buffer UNUSED,
			const jsmntok_t *config UNUSED)
{
	wait_and_check_bitcoind(init_cmd->plugin);

	/* Usually we fake up fees in regtest */
	if (streq(chainparams->network_name, "regtest"))
		bitcoind->fake_fees = !bitcoind->dev_no_fake_fees;
	else
		bitcoind->fake_fees = false;

	plugin_set_memleak_handler(init_cmd->plugin, memleak_mark_bitcoind);
	plugin_log(init_cmd->plugin, LOG_INFORM,
		   "bitcoin-cli initialized and connected to bitcoind.");

	return NULL;
}

static const struct plugin_command commands[] = {
	{
		"getrawblockbyheight",
		getrawblockbyheight
	},
	{
		"getchaininfo",
		getchaininfo
	},
	{
		"estimatefees",
		estimatefees
	},
	{
		"sendrawtransaction",
		sendrawtransaction
	},
	{
		"getutxout",
		getutxout
	},
};

static struct bitcoind *new_bitcoind(const tal_t *ctx)
{
	bitcoind = tal(ctx, struct bitcoind);

	bitcoind->cli = NULL;
	bitcoind->datadir = NULL;
	bitcoind->rpcuser = NULL;
	bitcoind->rpcpass = NULL;
	bitcoind->rpcconnect = NULL;
	bitcoind->rpcport = NULL;
	/* Do not exceed reasonable timeout to avoid bitcoind hang.
	   Although normal rpcclienttimeout default value is 900. */
	bitcoind->rpcclienttimeout = 60;
	bitcoind->dev_no_fake_fees = false;
	bitcoind->dev_ignore_ibd = false;

	return bitcoind;
}

int main(int argc, char *argv[])
{
	setup_locale();

	/* Initialize our global context object here to handle startup options. */
	bitcoind = new_bitcoind(NULL);

	plugin_main(argv, init, NULL, PLUGIN_STATIC, false /* Do not init RPC on startup*/,
		    NULL, commands, ARRAY_SIZE(commands),
		    NULL, 0, NULL, 0, NULL, 0,
		    plugin_option("bitcoin-datadir",
				  "string",
				  "-datadir arg for bitcoin-cli",
				  charp_option, NULL, &bitcoind->datadir),
		    plugin_option("bitcoin-cli",
				  "string",
				  "bitcoin-cli pathname",
				  charp_option, NULL, &bitcoind->cli),
		    plugin_option("bitcoin-rpcuser",
				  "string",
				  "bitcoind RPC username",
				  charp_option, NULL, &bitcoind->rpcuser),
		    plugin_option("bitcoin-rpcpassword",
				  "string",
				  "bitcoind RPC password",
				  charp_option, NULL, &bitcoind->rpcpass),
		    plugin_option("bitcoin-rpcconnect",
				  "string",
				  "bitcoind RPC host to connect to",
				  charp_option, NULL, &bitcoind->rpcconnect),
		    plugin_option("bitcoin-rpcport",
				  "int",
				  "bitcoind RPC host's port",
				  charp_option, NULL, &bitcoind->rpcport),
		    plugin_option("bitcoin-rpcclienttimeout",
				  "int",
				  "bitcoind RPC timeout in seconds during HTTP requests",
				  u64_option, u64_jsonfmt, &bitcoind->rpcclienttimeout),
		    plugin_option("bitcoin-retry-timeout",
				  "int",
				  "how long to keep retrying to contact bitcoind"
				  " before fatally exiting",
				  u64_option, u64_jsonfmt, &bitcoind->retry_timeout),
		    plugin_option_dev("dev-no-fake-fees",
				      "bool",
				      "Suppress fee faking for regtest",
				      bool_option, NULL, &bitcoind->dev_no_fake_fees),
		    plugin_option_dev("dev-ignore-ibd",
				      "bool",
				      "Never tell lightningd we're doing initial block download",
				      bool_option, NULL, &bitcoind->dev_ignore_ibd),
		    NULL);
}
