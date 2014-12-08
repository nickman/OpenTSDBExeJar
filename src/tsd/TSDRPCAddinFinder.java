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

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Constructor;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;

import javassist.ClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.LoaderClassPath;
import net.opentsdb.core.TSDB;
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
	/** The config key for the Addin RPCs classpath */
	public static final String ADDIN_CP = "tsd.addin.rpcs.classpath";
	/** The config key for the Addin RPCs package name restrictions */
	public static final String ADDIN_PACKAGES = "tsd.addin.rpcs.packages";
	/** Empty String const */
	private static final String[] EMPTY_ARR = {};
	/** Static class logger */
	private static final Logger LOG = LoggerFactory.getLogger(TSDRPCAddinFinder.class);
	
	
	/** The configured addin classpaths */
	protected final String[] addinClasspaths;
	/** The configured addin package name restrictions */
	protected final String[] addinPackages;
	
	/** The located annotated HttpRpc impls */
	protected final Map<String, HttpRpc> httpImpls = new HashMap<String, HttpRpc>(); 
	/** The located annotated TelnetRpc impls */
	protected final Map<String, TelnetRpc> telnetImpls = new HashMap<String, TelnetRpc>(); 
	/** The TSDB instance */
	protected final TSDB tsdb;
	
	
	
	/**
	 * Creates a new TSDRPCAddinFinder
	 * @param tsdb The TSDB instance
	 */
	public TSDRPCAddinFinder(final TSDB tsdb) {
		this.tsdb = tsdb;
		// configure the classpaths to scan 
		addinClasspaths = preClean(tsdb.getConfig(), ADDIN_CP, gatherClasspaths());
		// configure the allowed packages 
		addinPackages = preClean(tsdb.getConfig(), ADDIN_PACKAGES);
	}
	
	@SuppressWarnings("resource")
	private String[] gatherClasspaths() {
		final Set<File> fpaths = new LinkedHashSet<File>();
		final Set<String> paths = new LinkedHashSet<String>();
		for(String s: ManagementFactory.getRuntimeMXBean().getClassPath().split(File.pathSeparator)) {
			File f = new File(s);
			if(f.exists()) {
				fpaths.add(f.getAbsoluteFile());
			}
			paths.add(s);
		}
		//Collections.addAll(paths, ManagementFactory.getRuntimeMXBean().getClassPath().split(File.pathSeparator));
		// Get the system class loader URLs, since the TSDB forces classpath changes by adding URLS
		// directly to the URLClassLoader, so they don't show up in the RuntimeMXBean
		URLClassLoader ucl = (URLClassLoader)ClassLoader.getSystemClassLoader();
		URL[] urls = ucl.getURLs();
		// Create an array of strings from the loaded URLs		
		for(int i = 0; i < urls.length; i++) {
			final URL url = urls[i];
			if("file".equals(url.getProtocol())) {
				File f = new File(url.getFile());
				if(f.exists()) {
					f = f.getAbsoluteFile();
					if(fpaths.add(f)) {
						paths.add(urls[i].toString());
					}
				}
			} else {
				paths.add(urls[i].toString());
			}
		}		
		return paths.toArray(new String[paths.size()]);
	}
	
	/**
	 * Executes the classpath scan
	 * @return true if any @RPCs were found, false otherwise
	 */
	public boolean scan() {
		final long start = System.currentTimeMillis();
		for(String s: addinClasspaths) {		
			LOG.debug("Inspecting classpath: {}", s);
			File f = new File(s.trim());
			if(f.exists()) {
				if(f.isDirectory()) {
					scan(f.getAbsoluteFile());
				}
			} else {
				try {
					URL url = new URL(s.trim());
					scan(url);
				} catch (Exception x) {/* No Op */}
			}
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
	private static String[] preClean(final Config config, final String property, String...additional) {
		String[] args = config.hasProperty(property) ? config.getString(property).split(",") : null;
//		if(args==null || args.length==0) return EMPTY_ARR;
		Set<String> set = new LinkedHashSet<String>();
		if(args!=null) {
			for(int i = 0; i < args.length; i++) {
				if(args[i] == null || args[i].trim().isEmpty()) continue;
				set.add(args[i].trim());
			}
		}
		for(int i = 0; i < additional.length; i++) {
			if(additional[i] == null || additional[i].trim().isEmpty()) continue;
			set.add(additional[i].trim());
		}
		
		return set.toArray(new String[set.size()]);
	}
	
	/**
	 * Determines if the passed package name is in an allowed package
	 * @param packageName The package name to test
	 * @return true if allowed, false otherwise
	 */
	protected boolean isAllowedPackage(final String packageName) {
		if(addinPackages.length==0) return true;		
		for(int i = 0; i < addinPackages.length; i++) {
			if(packageName.indexOf(addinPackages[i])!=-1) return true;
		}
		return false;
	}
	

	/**
	 * Adds instances of the located RPC handlers to the impl maps
	 * @param clazz The located class
	 */
	protected void processRPCClass(final Class<?> clazz) {
		final RPC rpc = clazz.getAnnotation(RPC.class);
		if(rpc==null) return;
		try {
			final Object rpcInstance = buildRPCInstance(clazz, tsdb, rpc);
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
	 * Scans a file system directory for @RPC annotated classes
	 * @param dir The directory to scan
	 */
	protected void scan(final File dir) {
		LOG.debug("Scanning Dir {}", dir);
		final ClassPool cp = new ClassPool(true);		
		try {
			final ClassLoader CL = new URLClassLoader(new URL[]{dir.toURI().toURL()});
			final ClassPath path = new LoaderClassPath(CL); 
			cp.appendClassPath(path);
			final Set<File> classFiles = findClassFiles(dir, null);
			for(final File f: classFiles) {
				FileInputStream fis = null;
				try {
					fis = new FileInputStream(f);
					CtClass ctClazz = cp.makeClass(fis);
					for(Object ann: ctClazz.getAvailableAnnotations()) {
						if(RPC.class.isInstance(ann)) {
							if(isAllowedPackage(ctClazz.getPackageName())) {
								Class<?> instance = null;
								try {
									instance = Class.forName(ctClazz.getName(), true, CL);
								} catch (Exception ex) {/* No Op */}
								if(instance!=null) {
									processRPCClass(instance);
									break;
								}
								try {
									instance = ctClazz.toClass();
									LOG.debug("@RPC Match: {}", instance.getName()); 
									processRPCClass(instance);									
								} catch (Throwable t) {
									LOG.error("Failed to load class [{}] from path [{}]. Error: {}", ctClazz.getName(), dir, t.toString());
								}
								break;
							}
						}
					}
				} finally {
					if(fis!=null) try { fis.close(); } catch (Exception x) {/* No Op */}
				}
			}
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}		
	}
	
	/**
	 * Scans a Jar URL for @RPC annotated classes
	 * @param url The URL to scan
	 */
	protected void scan(final URL url) {
		if("file".equals(url.getProtocol())) {
			File d = new File(url.getFile());
			if(d.exists() && d.isDirectory()) {
				scan(d);
				return;
			}
		}
		final ClassLoader CL = new URLClassLoader(new URL[]{url});
		final ClassPath path = new LoaderClassPath(CL); 
		final ClassPool cp = new ClassPool(true);
		cp.appendClassPath(path);
		InputStream is = null;
		JarInputStream jarInputStream = null;
		try {
			is = url.openStream();
			jarInputStream = new JarInputStream(is);
			JarEntry je = null;
			while((je = jarInputStream.getNextJarEntry())!=null) {
				if(je.isDirectory() || !je.getName().endsWith(".class")) continue;
				CtClass ctClazz = cp.makeClass(jarInputStream);
				for(Object ann: ctClazz.getAvailableAnnotations()) {
					if(RPC.class.isInstance(ann)) {
						if(isAllowedPackage(ctClazz.getPackageName())) {
							Class<?> instance = null;
							try {
								instance = Class.forName(ctClazz.getName(), true, CL);
							} catch (Exception ex) {/* No Op */}
							if(instance!=null) {
								processRPCClass(instance);
								break;
							}
							
							try {
								instance = ctClazz.toClass();
								LOG.debug("@RPC Match: {}", instance.getName());
								processRPCClass(instance);
							} catch (Throwable t) {
								LOG.error("Failed to load class [{}] from path [{}]. Error: {}", ctClazz.getName(), url, t.toString());
							}
							break;
						}						
					}
				}
			}
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		} finally {
			if(jarInputStream!=null) try { jarInputStream.close(); } catch (Exception x) {/* No Op */}
			if(is!=null) try { is.close(); } catch (Exception x) {/* No Op */}
		}
	}
	
	/**
	 * Builds the RPC Class instance
	 * @param rpcClass The RPC class
	 * @param tsdb The TSDB instance
	 * @param rpc The RPC annotation
	 * @return the RPC instance
	 * @throws Exception thrown on any error 
	 */
	protected Object buildRPCInstance(final Class<?> rpcClass, final TSDB tsdb, final RPC rpc) throws Exception {
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
		} else {
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
	
		
	
	/**
	 * Recursive directory scanner to find class file
	 * @param dir The directory to scan
	 * @param accum The accumulated file set
	 * @return The located class files
	 */
	protected static Set<File> findClassFiles(final File dir, Set<File> accum) {
		if(accum==null) accum = new LinkedHashSet<File>();
		for(File f: dir.listFiles()) {
			if(f.isDirectory()) {
				findClassFiles(f, accum);
			} else {
				if(f.getName().endsWith(".class")) {
					accum.add(f.getAbsoluteFile());
				}
			}
		}
		return accum;
	}
	

}
