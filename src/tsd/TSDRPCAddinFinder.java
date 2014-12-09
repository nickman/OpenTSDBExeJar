/**
 * Helios, OpenSource Monitoring
 * Brought to you by the Helios Development Group
 *
 * Copyright 2007, Helios Development Group and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org. 
 *
 */
package net.opentsdb.tsd;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import net.opentsdb.core.TSDB;
import net.opentsdb.utils.AnnotationFinder;
import net.opentsdb.utils.Config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>Title: TSDRPCAddinFinder</p>
 * <p>Description: Finds, configures and loads TSD RPC Addins</p> 
 * <p>Company: Helios Development Group LLC</p>
 * @author Whitehead (nwhitehead AT heliosdev DOT org)
 * <p><code>net.opentsdb.tsd.TSDRPCAddinFinder</code></p>
 */

public class TSDRPCAddinFinder {
	/** The singleton instance */
	private static volatile TSDRPCAddinFinder instance = null;
	/** The singleton instance ctor lock */
	private static final Object lock = new Object();
	
	/** The config key for the Addin RPCs classpath */
	public static final String ADDIN_CP = "tsd.addin.rpcs.classpath";
	/** The config key for the Addin RPCs package name restrictions */
	public static final String ADDIN_PACKAGES = "tsd.addin.rpcs.packages";
	
	/** Empty String const */
	private static final String[] EMPTY_ARR = {};
	/** Static class logger */
	private static final Logger LOG = LoggerFactory.getLogger(TSDRPCAddinFinder.class);
	/** The TSDB instance */
	protected final TSDB tsdb;
	/** The annotation finder */
	protected final AnnotationFinder annotationFinder = new AnnotationFinder(true);
	
	/** A map of loaded HttpRpcs keyed by the invocation keys */
	protected final Map<String, HttpRpc> httpImpls = new HashMap<String, HttpRpc>();
	/** A map of loaded TelnetRpcs keyed by the invocation keys */
	protected final Map<String, TelnetRpc> telnetImpls = new HashMap<String, TelnetRpc>();
	
	/**
	 * Acquires the TSDRPCAddinFinder singleton instance
	 * @param tsdb The TSDB 
	 * @return the TSDRPCAddinFinder singleton instance
	 */
	public static TSDRPCAddinFinder getInstance(final TSDB tsdb) {
		if(tsdb==null) throw new IllegalArgumentException("The passed TSDB instance was null");
		if(instance==null) {
			synchronized(lock) {
				if(instance==null) {
					instance = new TSDRPCAddinFinder(tsdb);
				}
			}
		}
		return instance;
	}
	
	
	/**
	 * Creates a new TSDRPCAddinFinder
	 * @param tsdb The TSDB instance
	 */
	private TSDRPCAddinFinder(final TSDB tsdb) {
		this.tsdb = tsdb;
		// configure the classpaths to scan
		annotationFinder.appendPaths(preClean(tsdb.getConfig(), ADDIN_CP))
			.appendAllowedPackages(preClean(tsdb.getConfig(), ADDIN_PACKAGES))
			.addAttributeDecoderMap("c", tsdb.getConfig().getMap());
	}
	
	
	/**
	 * Executes the classpath scan
	 * @return true if any @RPCs were found and indexed, false otherwise
	 */
	public boolean scan() {
		final long start = System.currentTimeMillis();
		final Collection<Class<?>> locatedRPCClasses = annotationFinder.scan(RPC.class);
		LOG.info("Located [{}] candidate classes annotated with @RPC", locatedRPCClasses);
		for(Class<?> clazz: locatedRPCClasses) {
			processRPCClass(clazz);
		}
		final long elapsed = System.currentTimeMillis() - start;
		LOG.info("Completed @RPC Scan in {} ms. Located:\n\tHttpRpcs: {}\n\tTelnetRpcs: {}", elapsed, httpImpls.size(), telnetImpls.size());
		return !(httpImpls.isEmpty() && telnetImpls.isEmpty());
	}
	
	/**
	 * Returns the located annotated HttpRpcs
	 * @return A map of HttpRpcs keyed by the invocation key
	 */
	public Map<String, HttpRpc> getLocatedHttpRpcs() {
		return httpImpls;
	}
	
	/**
	 * Returns the located annotated TelnetRpcs
	 * @return A map of TelnetRpcs keyed by the invocation key
	 */
	public Map<String, TelnetRpc> getLocatedTelnetRpcs() {
		return telnetImpls;
	}
	
	
	
	
	/**
	 * Cleans and trims the classpaths and packages
	 * @param config The TSDB Config to load props from
	 * @param property The property key to load the value for
	 * @param additional Optional additional values to add
	 * @return A cleaned string array
	 */
	private static String[] preClean(final Config config, final String property) {
		String[] args = config.hasProperty(property) ? config.getString(property).split(",") : EMPTY_ARR;
		Set<String> set = new LinkedHashSet<String>();
		if(args!=null) {
			for(int i = 0; i < args.length; i++) {
				if(args[i] == null || args[i].trim().isEmpty()) continue;
				set.add(args[i].trim());
			}
		}
		return set.toArray(new String[set.size()]);
	}
	
	

	/**
	 * Adds instances of the located RPC handlers to the impl maps
	 * @param clazz The located class
	 */
	protected void processRPCClass(final Class<?> clazz) {
		final RPC rpc = annotationFinder.getAnnotation(clazz, RPC.class); 				
		if(rpc==null) return;
		try {
			final Object rpcInstance = buildRPCInstance(clazz, rpc);
			String[] names = rpc.httpKeys();
			if(names.length>0 && rpcInstance instanceof HttpRpc) {		
				try {
					final HttpRpc httpRpc = (HttpRpc)rpcInstance;
					for(final String name: names) {
						if(httpImpls.containsKey(name)) {
							HttpRpc wasHereFirst = httpImpls.get(name); 
							LOG.warn("Configured key {} for HttpRpc {} already allocated for {}", name, clazz.getName(), wasHereFirst.getClass().getName());
						} else {
							httpImpls.put(name, httpRpc);
						}
					}
				} catch (Exception ex) {
					LOG.error("Failed to process installation of HttpRpc class [{}]", clazz.getName(), ex);
					throw new RuntimeException("Failed to process installation of HttpRpc class:" + clazz.getName(), ex);
				}
			}
			names = rpc.telnetKeys();
			if(names.length>0 && rpcInstance instanceof TelnetRpc) {
				try {
					final TelnetRpc telnetRpc = (TelnetRpc)rpcInstance;
					for(final String name: names) {
						if(telnetImpls.containsKey(name)) {
							TelnetRpc wasHereFirst = telnetImpls.get(name); 
							LOG.warn("Configured key {} for TelnetRpc {} already allocated for {}", name, clazz.getName(), wasHereFirst.getClass().getName());
						} else {
							telnetImpls.put(name, telnetRpc);
						}
					}
				} catch (Exception ex) {
					LOG.error("Failed to process installation of TelnetRpc class [{}]", clazz.getName(), ex);
					throw new RuntimeException("Failed to process installation of TelnetRpc class:" + clazz.getName(), ex);
				}					
			}			
		} catch (Exception ex) {
			throw new RuntimeException("Failed to process RPC Class " + clazz.getName(), ex);
		}
	}
	
	
	
	/**
	 * Builds the RPC Class instance
	 * @param rpcClass The RPC class
	 * @param rpc The RPC annotation
	 * @return the RPC instance
	 * @throws Exception thrown on any error 
	 */
	protected Object buildRPCInstance(final Class<?> rpcClass, final RPC rpc) throws Exception {
		boolean withTSDBArg = true;
		if(rpc.singleton()) {
			Method m = null;			 
			try {
				m = rpcClass.getDeclaredMethod("getInstance", TSDB.class);
				withTSDBArg = true;
			} catch (NoSuchMethodException nsme) {
				m = rpcClass.getDeclaredMethod("getInstance");
				withTSDBArg = false;
			}
			if(!Modifier.isStatic(rpcClass.getModifiers())) {
				LOG.error("RPC Class [{}] is annotated as a singleton but getInstance method was not static", rpcClass.getName());
				throw new Exception("RPC Class " + rpcClass.getName() + " is annotated as a singleton but getInstance method was not static");
			}
			return withTSDBArg ? m.invoke(null, tsdb) : m.invoke(null); 					
		}
		Constructor<?> ctor = null;
		try {
			ctor = rpcClass.getDeclaredConstructor(TSDB.class);
			withTSDBArg = true;
		} catch (NoSuchMethodException nsme) {
			ctor = rpcClass.getDeclaredConstructor();
			withTSDBArg = false;
		}
		return withTSDBArg ? ctor.newInstance(tsdb) : ctor.newInstance();
	}

}
