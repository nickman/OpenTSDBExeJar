// This file is part of OpenTSDB.
// Copyright (C) 2010-2012  The OpenTSDB Authors.
//
// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 2.1 of the License, or (at your
// option) any later version.  This program is distributed in the hope that it
// will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
// of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser
// General Public License for more details.  You should have received a copy
// of the GNU Lesser General Public License along with this program.  If not,
// see <http://www.gnu.org/licenses/>.
package net.opentsdb.tsd;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import net.opentsdb.BuildData;
import net.opentsdb.core.Aggregators;
import net.opentsdb.core.TSDB;
import net.opentsdb.stats.StatsCollector;
import net.opentsdb.utils.Config;
import net.opentsdb.utils.JSON;

import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.jboss.netty.handler.codec.http.HttpMethod;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpResponseStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.net.HttpHeaders;
import com.stumbleupon.async.Callback;
import com.stumbleupon.async.Deferred;

/**
 * Stateless handler for RPCs (telnet-style or HTTP).
 */
final class RpcHandler extends SimpleChannelUpstreamHandler {

  private static final Logger LOG = LoggerFactory.getLogger(RpcHandler.class);

  private static final AtomicLong telnet_rpcs_received = new AtomicLong();
  private static final AtomicLong http_rpcs_received = new AtomicLong();
  private static final AtomicLong exceptions_caught = new AtomicLong();

  /** Commands we can serve on the simple, telnet-style RPC interface. */
  private final HashMap<String, TelnetRpc> telnet_commands;
  /** RPC executed when there's an unknown telnet-style command. */
  private final TelnetRpc unknown_cmd = new Unknown();
  /** Commands we serve on the HTTP interface. */
  private final HashMap<String, HttpRpc> http_commands;
  /** List of domains to allow access to HTTP. By default this will be empty and
   * all CORS headers will be ignored. */
  private final HashSet<String> cors_domains;
  /** List of headers allowed for access to HTTP. By default this will contain a
   * set of known-to-work headers */
  private final String cors_headers;

  /** The TSDB to use. */
  private final TSDB tsdb;
  
	/** The config key for the TSD RPC addin classes */
	public static final String TSD_RPC_ADDIN_KEY = "tsd.addins.rpcs";
	/** The config key for the TSD RPC addin classpath */
	public static final String TSD_RPC_ADDIN_CP_KEY = "tsd.addins.rpcs.classpath";
	/** The template for the classloader MBean's ObjectName */
	public static final String CLASSLOADER_OBJECTNAME = "net.opentsdb.classpath:type=ClassLoader,name=%s.classpath";
	

  /**
   * Constructor that loads the CORS domain list and configures the route maps 
   * for telnet and HTTP requests
   * @param tsdb The TSDB to use.
   * @throws IllegalArgumentException if there was an error with the CORS domain
   * list
   */
  public RpcHandler(final TSDB tsdb) {
    this.tsdb = tsdb;

    final String cors = tsdb.getConfig().getString("tsd.http.request.cors_domains");
    final String mode = tsdb.getConfig().getString("tsd.mode");

    LOG.info("TSD is in " + mode + " mode");

    if (cors == null || cors.isEmpty()) {
      cors_domains = null;
      LOG.info("CORS domain list was empty, CORS will not be enabled");
    } else {
      final String[] domains = cors.split(",");
      cors_domains = new HashSet<String>(domains.length);
      for (final String domain : domains) {
        if (domain.equals("*") && domains.length > 1) {
          throw new IllegalArgumentException(
              "tsd.http.request.cors_domains must be a public resource (*) or " 
              + "a list of specific domains, you cannot mix both.");
        }
        cors_domains.add(domain.trim().toUpperCase());
        LOG.info("Loaded CORS domain (" + domain + ")");
      }
    }

    cors_headers = tsdb.getConfig().getString("tsd.http.request.cors_headers")
        .trim();
    if ((cors_headers == null) || !cors_headers.matches("^([a-zA-Z0-9_.-]+,\\s*)*[a-zA-Z0-9_.-]+$")) {
      throw new IllegalArgumentException(
          "tsd.http.request.cors_headers must be a list of validly-formed "
          + "HTTP header names. No wildcards are allowed.");
    } else {
      LOG.info("Loaded CORS headers (" + cors_headers + ")");
    }

    telnet_commands = new HashMap<String, TelnetRpc>();
    http_commands = new HashMap<String, HttpRpc>();
    if (mode.equals("rw") || mode.equals("wo")) {
      final PutDataPointRpc put = new PutDataPointRpc();
      telnet_commands.put("put", put);
      http_commands.put("api/put", put);
    }

    if (mode.equals("rw") || mode.equals("ro")) {
      http_commands.put("", new HomePage());
      final StaticFileRpc staticfile = new StaticFileRpc();
      http_commands.put("favicon.ico", staticfile);
      http_commands.put("s", staticfile);

      final StatsRpc stats = new StatsRpc();
      telnet_commands.put("stats", stats);
      http_commands.put("stats", stats);
      http_commands.put("api/stats", stats);

      final DropCaches dropcaches = new DropCaches();
      telnet_commands.put("dropcaches", dropcaches);
      http_commands.put("dropcaches", dropcaches);
      http_commands.put("api/dropcaches", dropcaches);

      final ListAggregators aggregators = new ListAggregators();
      http_commands.put("aggregators", aggregators);
      http_commands.put("api/aggregators", aggregators);

      final SuggestRpc suggest_rpc = new SuggestRpc();
      http_commands.put("suggest", suggest_rpc);
      http_commands.put("api/suggest", suggest_rpc);

      http_commands.put("logs", new LogsRpc());
      http_commands.put("q", new GraphHandler());
      http_commands.put("api/serializers", new Serializers());
      http_commands.put("api/uid", new UniqueIdRpc());
      http_commands.put("api/query", new QueryRpc());
      http_commands.put("api/tree", new TreeRpc());
      http_commands.put("api/annotation", new AnnotationRpc());
      http_commands.put("api/search", new SearchRpc());
      http_commands.put("api/config", new ShowConfig());
    }

    if (tsdb.getConfig().getString("tsd.no_diediedie").equals("false")) {
      final DieDieDie diediedie = new DieDieDie();
      telnet_commands.put("diediedie", diediedie);
      http_commands.put("diediedie", diediedie);
    }
    {
      final Version version = new Version();
      telnet_commands.put("version", version);
      http_commands.put("version", version);
      http_commands.put("api/version", version);
    }

    telnet_commands.put("exit", new Exit());
    telnet_commands.put("help", new Help());
    
    installAddinRPCs();
  }

  @Override
  public void messageReceived(final ChannelHandlerContext ctx,
                              final MessageEvent msgevent) {
    try {
      final Object message = msgevent.getMessage();
      if (message instanceof String[]) {
        handleTelnetRpc(msgevent.getChannel(), (String[]) message);
      } else if (message instanceof HttpRequest) {
        handleHttpQuery(tsdb, msgevent.getChannel(), (HttpRequest) message);
      } else {
        logError(msgevent.getChannel(), "Unexpected message type "
                 + message.getClass() + ": " + message);
        exceptions_caught.incrementAndGet();
      }
    } catch (Exception e) {
      Object pretty_message = msgevent.getMessage();
      if (pretty_message instanceof String[]) {
        pretty_message = Arrays.toString((String[]) pretty_message);
      }
      logError(msgevent.getChannel(), "Unexpected exception caught"
               + " while serving " + pretty_message, e);
      exceptions_caught.incrementAndGet();
    }
  }

  /**
   * Finds the right handler for a telnet-style RPC and executes it.
   * @param chan The channel on which the RPC was received.
   * @param command The split telnet-style command.
   */
  private void handleTelnetRpc(final Channel chan, final String[] command) {
    TelnetRpc rpc = telnet_commands.get(command[0]);
    if (rpc == null) {
      rpc = unknown_cmd;
    }
    telnet_rpcs_received.incrementAndGet();
    rpc.execute(tsdb, chan, command);
  }

  /**
   * Finds the right handler for an HTTP query and executes it.
   * Also handles simple and pre-flight CORS requests if configured, rejecting
   * requests that do not match a domain in the list.
   * @param chan The channel on which the query was received.
   * @param req The parsed HTTP request.
   */
  private void handleHttpQuery(final TSDB tsdb, final Channel chan, final HttpRequest req) {
    http_rpcs_received.incrementAndGet();
    final HttpQuery query = new HttpQuery(tsdb, req, chan);
    if (!tsdb.getConfig().enable_chunked_requests() && req.isChunked()) {
      logError(query, "Received an unsupported chunked request: "
               + query.request());
      query.badRequest("Chunked request not supported.");
      return;
    }
    try {
      try {        
        final String route = query.getQueryBaseRoute();
        query.setSerializer();
        
        final String domain = req.headers().get("Origin");
        
        // catch CORS requests and add the header or refuse them if the domain
        // list has been configured
        if (query.method() == HttpMethod.OPTIONS || 
            (cors_domains != null && domain != null && !domain.isEmpty())) {          
          if (cors_domains == null || domain == null || domain.isEmpty()) {
            throw new BadRequestException(HttpResponseStatus.METHOD_NOT_ALLOWED, 
                "Method not allowed", "The HTTP method [" + 
                query.method().getName() + "] is not permitted");
          }
          
          if (cors_domains.contains("*") || 
              cors_domains.contains(domain.toUpperCase())) {

            // when a domain has matched successfully, we need to add the header
            query.response().headers().add(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN,
                domain);
            query.response().headers().add(HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS,
                "GET, POST, PUT, DELETE");
            query.response().headers().add(HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS,
                cors_headers);

            // if the method requested was for OPTIONS then we'll return an OK
            // here and no further processing is needed.
            if (query.method() == HttpMethod.OPTIONS) {
              query.sendStatusOnly(HttpResponseStatus.OK);
              return;
            }
          } else {
            // You'd think that they would want the server to return a 403 if
            // the Origin wasn't in the CORS domain list, but they want a 200
            // without the allow origin header. We'll return an error in the
            // body though.
            throw new BadRequestException(HttpResponseStatus.OK, 
                "CORS domain not allowed", "The domain [" + domain + 
                "] is not permitted access");
          }
        }
        
        final HttpRpc rpc = http_commands.get(route);
        if (rpc != null) {
          rpc.execute(tsdb, query);
        } else {
          query.notFound();
        }
      } catch (BadRequestException ex) {
        query.badRequest(ex);
      }
    } catch (Exception ex) {
      query.internalError(ex);
      exceptions_caught.incrementAndGet();
    }
  }

  /**
   * Collects the stats and metrics tracked by this instance.
   * @param collector The collector to use.
   */
  public static void collectStats(final StatsCollector collector) {
    collector.record("rpc.received", telnet_rpcs_received, "type=telnet");
    collector.record("rpc.received", http_rpcs_received, "type=http");
    collector.record("rpc.exceptions", exceptions_caught);
    HttpQuery.collectStats(collector);
    GraphHandler.collectStats(collector);
    PutDataPointRpc.collectStats(collector);
  }

  // ---------------------------- //
  // Individual command handlers. //
  // ---------------------------- //

  /** The "diediedie" command and "/diediedie" endpoint. */
  private final class DieDieDie implements TelnetRpc, HttpRpc {
    public Deferred<Object> execute(final TSDB tsdb, final Channel chan,
                                    final String[] cmd) {
      logWarn(chan, "shutdown requested");
      chan.write("Cleaning up and exiting now.\n");
      return doShutdown(tsdb, chan);
    }

    public void execute(final TSDB tsdb, final HttpQuery query) {
      logWarn(query, "shutdown requested");
      query.sendReply(HttpQuery.makePage("TSD Exiting", "You killed me",
                                         "Cleaning up and exiting now."));
      doShutdown(tsdb, query.channel());
    }

    private Deferred<Object> doShutdown(final TSDB tsdb, final Channel chan) {
      ((GraphHandler) http_commands.get("q")).shutdown();
      ConnectionManager.closeAllConnections();
      // Netty gets stuck in an infinite loop if we shut it down from within a
      // NIO thread.  So do this from a newly created thread.
      final class ShutdownNetty extends Thread {
        ShutdownNetty() {
          super("ShutdownNetty");
        }
        public void run() {
          chan.getFactory().releaseExternalResources();
        }
      }
      new ShutdownNetty().start();  // Stop accepting new connections.

      // Log any error that might occur during shutdown.
      final class ShutdownTSDB implements Callback<Exception, Exception> {
        public Exception call(final Exception arg) {
          LOG.error("Unexpected exception while shutting down", arg);
          return arg;
        }
        public String toString() {
          return "shutdown callback";
        }
      }
      return tsdb.shutdown().addErrback(new ShutdownTSDB());
    }
  }

  /** The "exit" command. */
  private static final class Exit implements TelnetRpc {
    public Deferred<Object> execute(final TSDB tsdb, final Channel chan,
                                    final String[] cmd) {
      chan.disconnect();
      return Deferred.fromResult(null);
    }
  }

  /** The "help" command. */
  private final class Help implements TelnetRpc {
    public Deferred<Object> execute(final TSDB tsdb, final Channel chan,
                                    final String[] cmd) {
      final StringBuilder buf = new StringBuilder();
      buf.append("available commands: ");
      // TODO(tsuna): Maybe sort them?
      for (final String command : telnet_commands.keySet()) {
        buf.append(command).append(' ');
      }
      buf.append('\n');
      chan.write(buf.toString());
      return Deferred.fromResult(null);
    }
  }

  /** The home page ("GET /"). */
  private static final class HomePage implements HttpRpc {
    public void execute(final TSDB tsdb, final HttpQuery query) 
      throws IOException {
      final StringBuilder buf = new StringBuilder(2048);
      buf.append("<div id=queryuimain></div>"
                 + "<noscript>You must have JavaScript enabled.</noscript>"
                 + "<iframe src=javascript:'' id=__gwt_historyFrame tabIndex=-1"
                 + " style=position:absolute;width:0;height:0;border:0>"
                 + "</iframe>");
      query.sendReply(HttpQuery.makePage(
        "<script type=text/javascript language=javascript"
        + " src=/s/queryui.nocache.js></script>",
        "TSD", "Time Series Database", buf.toString()));
    }
  }

  /** The "/aggregators" endpoint. */
  private static final class ListAggregators implements HttpRpc {
    public void execute(final TSDB tsdb, final HttpQuery query) 
      throws IOException {
      
      // only accept GET/POST
      if (query.method() != HttpMethod.GET && query.method() != HttpMethod.POST) {
        throw new BadRequestException(HttpResponseStatus.METHOD_NOT_ALLOWED, 
            "Method not allowed", "The HTTP method [" + query.method().getName() +
            "] is not permitted for this endpoint");
      }
      
      if (query.apiVersion() > 0) {
        query.sendReply(
            query.serializer().formatAggregatorsV1(Aggregators.set()));
      } else {
        query.sendReply(JSON.serializeToBytes(Aggregators.set()));
      }
    }
  }

  /** For unknown commands. */
  private static final class Unknown implements TelnetRpc {
    public Deferred<Object> execute(final TSDB tsdb, final Channel chan,
                                    final String[] cmd) {
      logWarn(chan, "unknown command : " + Arrays.toString(cmd));
      chan.write("unknown command: " + cmd[0] + ".  Try `help'.\n");
      return Deferred.fromResult(null);
    }
  }

  /** The "version" command. */
  private static final class Version implements TelnetRpc, HttpRpc {
    public Deferred<Object> execute(final TSDB tsdb, final Channel chan,
                                    final String[] cmd) {
      if (chan.isConnected()) {
        chan.write(BuildData.revisionString() + '\n'
                   + BuildData.buildString() + '\n');
      }
      return Deferred.fromResult(null);
    }

    public void execute(final TSDB tsdb, final HttpQuery query) throws 
      IOException {
      
      // only accept GET/POST
      if (query.method() != HttpMethod.GET && query.method() != HttpMethod.POST) {
        throw new BadRequestException(HttpResponseStatus.METHOD_NOT_ALLOWED, 
            "Method not allowed", "The HTTP method [" + query.method().getName() +
            "] is not permitted for this endpoint");
      }
      
      final HashMap<String, String> version = new HashMap<String, String>();
      version.put("version", BuildData.version);
      version.put("short_revision", BuildData.short_revision);
      version.put("full_revision", BuildData.full_revision);
      version.put("timestamp", Long.toString(BuildData.timestamp));
      version.put("repo_status", BuildData.repo_status.toString());
      version.put("user", BuildData.user);
      version.put("host", BuildData.host);
      version.put("repo", BuildData.repo);
      
      if (query.apiVersion() > 0) {
        query.sendReply(query.serializer().formatVersionV1(version));
      } else {
        final boolean json = query.request().getUri().endsWith("json");      
        if (json) {
          query.sendReply(JSON.serializeToBytes(version));
        } else {
          final String revision = BuildData.revisionString();
          final String build = BuildData.buildString();
          StringBuilder buf;
          buf = new StringBuilder(2 // For the \n's
                                  + revision.length() + build.length());
          buf.append(revision).append('\n').append(build).append('\n');
          query.sendReply(buf);
        }
      }
    }
  }

  /**
   * Returns the directory path stored in the given system property.
   * @param prop The name of the system property.
   * @return The directory path.
   * @throws IllegalStateException if the system property is not set
   * or has an invalid value.
   */
  static String getDirectoryFromSystemProp(final String prop) {
    final String dir = System.getProperty(prop);
    String err = null;
    if (dir == null) {
      err = "' is not set.";
    } else if (dir.isEmpty()) {
      err = "' is empty.";
    } else if (dir.charAt(dir.length() - 1) != '/') {  // Screw Windows.
      err = "' is not terminated with `/'.";
    }
    if (err != null) {
      throw new IllegalStateException("System property `" + prop + err);
    }
    return dir;
  }

  /** The "dropcaches" command. */
  private static final class DropCaches implements TelnetRpc, HttpRpc {
    public Deferred<Object> execute(final TSDB tsdb, final Channel chan,
                                    final String[] cmd) {
      dropCaches(tsdb, chan);
      chan.write("Caches dropped.\n");
      return Deferred.fromResult(null);
    }

    public void execute(final TSDB tsdb, final HttpQuery query) 
      throws IOException {
      dropCaches(tsdb, query.channel());
      
      // only accept GET/POST
      if (query.method() != HttpMethod.GET && query.method() != HttpMethod.POST) {
        throw new BadRequestException(HttpResponseStatus.METHOD_NOT_ALLOWED, 
            "Method not allowed", "The HTTP method [" + query.method().getName() +
            "] is not permitted for this endpoint");
      }
      
      if (query.apiVersion() > 0) {
        final HashMap<String, String> response = new HashMap<String, String>();
        response.put("status", "200");
        response.put("message", "Caches dropped");
        query.sendReply(query.serializer().formatDropCachesV1(response));
      } else { // deprecated API
        query.sendReply("Caches dropped.\n");
      }
    }

    /** Drops in memory caches.  */
    private void dropCaches(final TSDB tsdb, final Channel chan) {
      LOG.warn(chan + " Dropping all in-memory caches.");
      tsdb.dropCaches();
    }
  }

  /** The /api/formatters endpoint 
   * @since 2.0 */
  private static final class Serializers implements HttpRpc {
    public void execute(final TSDB tsdb, final HttpQuery query) 
      throws IOException {
      // only accept GET/POST
      if (query.method() != HttpMethod.GET && query.method() != HttpMethod.POST) {
        throw new BadRequestException(HttpResponseStatus.METHOD_NOT_ALLOWED, 
            "Method not allowed", "The HTTP method [" + query.method().getName() +
            "] is not permitted for this endpoint");
      }
      
      switch (query.apiVersion()) {
        case 0:
        case 1:
          query.sendReply(query.serializer().formatSerializersV1());
          break;
        default: 
          throw new BadRequestException(HttpResponseStatus.NOT_IMPLEMENTED, 
              "Requested API version not implemented", "Version " + 
              query.apiVersion() + " is not implemented");
      }
    }
  }
  
  private static final class ShowConfig implements HttpRpc {

    @Override
    public void execute(TSDB tsdb, HttpQuery query) throws IOException {
   // only accept GET/POST
      if (query.method() != HttpMethod.GET && query.method() != HttpMethod.POST) {
        throw new BadRequestException(HttpResponseStatus.METHOD_NOT_ALLOWED, 
            "Method not allowed", "The HTTP method [" + query.method().getName() +
            "] is not permitted for this endpoint");
      }
      
      switch (query.apiVersion()) {
        case 0:
        case 1:
          query.sendReply(query.serializer().formatConfigV1(tsdb.getConfig()));
          break;
        default: 
          throw new BadRequestException(HttpResponseStatus.NOT_IMPLEMENTED, 
              "Requested API version not implemented", "Version " + 
              query.apiVersion() + " is not implemented");
      }
    }
    
  }
  
  // ---------------- //
  // Logging helpers. //
  // ---------------- //

  //private static void logInfo(final HttpQuery query, final String msg) {
  //  LOG.info(query.channel().toString() + ' ' + msg);
  //}

  private static void logWarn(final HttpQuery query, final String msg) {
    LOG.warn(query.channel().toString() + ' ' + msg);
  }

  //private void logWarn(final HttpQuery query, final String msg,
  //                     final Exception e) {
  //  LOG.warn(query.channel().toString() + ' ' + msg, e);
  //}

  private void logError(final HttpQuery query, final String msg) {
    LOG.error(query.channel().toString() + ' ' + msg);
  }

  //private static void logError(final HttpQuery query, final String msg,
  //                             final Exception e) {
  //  LOG.error(query.channel().toString() + ' ' + msg, e);
  //}

  //private void logInfo(final Channel chan, final String msg) {
  //  LOG.info(chan.toString() + ' ' + msg);
  //}

  private static void logWarn(final Channel chan, final String msg) {
    LOG.warn(chan.toString() + ' ' + msg);
  }

  //private void logWarn(final Channel chan, final String msg, final Exception e) {
  //  LOG.warn(chan.toString() + ' ' + msg, e);
  //}

  private void logError(final Channel chan, final String msg) {
    LOG.error(chan.toString() + ' ' + msg);
  }

  private void logError(final Channel chan, final String msg, final Exception e) {
    LOG.error(chan.toString() + ' ' + msg, e);
  }
  
	//================================================================================================
	//	  RPC Addins
	//================================================================================================
	
	
	/**
	 * Installs the Addin RPCs
	 */
	protected void installAddinRPCs() {
		final TSDRPCAddinFinder finder = new TSDRPCAddinFinder(tsdb);
		final Set<String> skipped = new HashSet<String>();
		if(finder.scan()) {
			int installed = 0;
			for(Map.Entry<String, HttpRpc> entry: finder.getLocatedHttpRpcs().entrySet()) {
				final String noInstallKey = "rpcskip.http." + entry.getValue().getClass().getName();
				if(System.getProperties().containsKey(noInstallKey)) {
					if(skipped.add(noInstallKey)) {
						LOG.info("Skipping Install of @RPC annotated HttpRpc instance [{}] because the system property [{}] was set", entry.getValue().getClass().getName(), noInstallKey);
					}
					continue;
				}
				final String rpcKey = decodeKey(entry.getKey(), tsdb.getConfig());
				if(rpcKey==null || rpcKey.trim().isEmpty()) {
					LOG.warn("Ignoring blank or null rpc key for HttpRpc class [{}]", entry.getValue().getClass().getName());
					continue;
				}				
				if(http_commands.containsKey(entry.getKey())) {
					LOG.warn("Skipping Addin HttpRpc [{}] because it's key [{}] is already registered", entry.getValue().getClass().getName(), rpcKey);
				} else {
					http_commands.put(rpcKey, entry.getValue());
					installed++;
					LOG.info("Installed Addin HttpRpc [{}] under key [{}]", entry.getValue().getClass().getName(), rpcKey);
				}
			}
			LOG.info("Installed {} Addin HttpRpcs", installed);		
			if(!skipped.isEmpty()) {
				LOG.info("Skipped {} Addin HttpRpcs", skipped.size());
				skipped.clear();
			}
			
			installed = 0;
			for(Map.Entry<String, TelnetRpc> entry: finder.getLocatedTelnetRpcs().entrySet()) {
				final String noInstallKey = "rpcskip.telnet." + entry.getValue().getClass().getName();
				if(System.getProperties().containsKey(noInstallKey)) {
					if(skipped.add(noInstallKey)) {
						LOG.info("Skipping Install of @RPC annotated TelnetRpc instance [{}] because the system property [{}] was set", entry.getValue().getClass().getName(), noInstallKey);
					}
					continue;
				}				
				final String rpcKey = decodeKey(entry.getKey(), tsdb.getConfig());
				if(rpcKey==null || rpcKey.trim().isEmpty()) {
					LOG.warn("Ignoring blank or null rpc key for TelnetRpc class [{}]", entry.getValue().getClass().getName());
					continue;
				}
				if(telnet_commands.containsKey(entry.getKey())) {
					LOG.warn("Skipping Addin TelnetRpc [{}] because it's key [{}] is already registered", entry.getValue().getClass().getName(), rpcKey);
				} else {
					telnet_commands.put(rpcKey, entry.getValue());
					installed++;
					LOG.info("Installed Addin TelnetRpc [{}] under key [{}]", entry.getValue().getClass().getName(), rpcKey);
				}
			}
			LOG.info("Installed {} Addin TelnetRpcs", installed);
			if(!skipped.isEmpty()) {
				LOG.info("Skipped {} Addin TelnetRpcs", skipped.size());
			}
		}
	}
	
	
	
	/** Key token pattern for System Property token substitution */
	public static final Pattern SYSPROP_PATTERN = Pattern.compile("\\$s\\{(.*?)(?::(.*?))?\\}");
	/** Key token pattern for Environment Variable token substitution */
	public static final Pattern ENV_PATTERN = Pattern.compile("\\$e\\{(.*?)(?::(.*?))?\\}");
	/** Key token pattern for TSDB Config token substitution */
	public static final Pattern CONFIG_PATTERN = Pattern.compile("\\$c\\{(.*?)(?::(.*?))?\\}");
	
	/** The JVM system properties as a string map */
	public static final Map<String, String> SYSPROPS_AS_MAP = new HashMap<String, String>(System.getProperties().size());
	
	/**
	 * Returns the system prop string map, populating it if it was not already
	 * @return the system prop string map
	 */
	private static Map<String, String> getSysPropsMap() {
		if(SYSPROPS_AS_MAP.isEmpty()) {
			synchronized(SYSPROPS_AS_MAP) {
				if(SYSPROPS_AS_MAP.isEmpty()) {
					for(Map.Entry<Object, Object> entry: System.getProperties().entrySet()) {
						SYSPROPS_AS_MAP.put(entry.getKey().toString(), entry.getValue().toString());
					}					
				}
			}
		}
		return SYSPROPS_AS_MAP;
	}
	
	
	/**
	 * Accepts an @RPC key string and replaces any recognized tokens
	 * @param original The original annotation supplied key
	 * @param cfg The TSDB configuration
	 * @return the decoded key
	 */
	protected String decodeKey(final String original, final Config cfg) {
		String base = original;
		base = replace(base, SYSPROP_PATTERN, getSysPropsMap());
		base = replace(base, ENV_PATTERN, System.getenv());
		base = replace(base, CONFIG_PATTERN, cfg.getMap());
		return base;
	}
	
	/**
	 * Executes the token replacement for a given pattern
	 * @param base The base string to execute the replacement on
	 * @param pattern The pattern to execute the replacement with
	 * @param lookup The lookup map to read values from
	 * @return the replaced string
	 */
	protected String replace(final CharSequence base, final Pattern pattern, final Map<String, String> lookup) {
		final StringBuffer b = new StringBuffer();
		Matcher m = pattern.matcher(base);
		while(m.find()) {
			String defValue = m.group(2);
			if(defValue==null) defValue = "";
			
			String decoded = lookup.get(m.group(1));
			if(decoded==null) decoded = defValue.trim();
			
			m.appendReplacement(b, decoded);    
		}
		m.appendTail(b);
		return b.toString();
	}
	
	

	
	//================================================================================================

  

}
