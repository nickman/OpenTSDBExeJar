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
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javassist.ClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.LoaderClassPath;
import net.opentsdb.core.TSDB;
import net.opentsdb.utils.Config;

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
	
	
	
	
	
	/**
	 * Creates a new TSDRPCAddinFinder
	 * @param config The TSDB config
	 */
	public TSDRPCAddinFinder(final Config config) {
		// Get the system class loader URLs, since the TSDB forces classpath changes by adding URLS
		// directly to the URLClassLoader, so they don't show up in the RuntimeMXBean
		URLClassLoader ucl = (URLClassLoader)ClassLoader.getSystemClassLoader();
		URL[] urls = ucl.getURLs();
		// Create an array of strings from the loaded URLs
		final String[] cps = new String[urls.length];
		for(int i = 0; i < urls.length; i++) {
			cps[i] = urls[i].toString();
		}
		// configure the classpaths to scan 
		addinClasspaths = preClean(config, ADDIN_CP, cps);
		// configure the allowed packages 
		addinPackages = preClean(config, ADDIN_PACKAGES);
	}
	
	/**
	 * Executes the classpath scan
	 * @return true if any @RPCs were found, false otherwise
	 */
	public boolean scan() {
		final long start = System.currentTimeMillis();
		for(String s: addinClasspaths) {				
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
	
	
	private TSDRPCAddinFinder() {
		final URLClassLoader ucl = (URLClassLoader)ClassLoader.getSystemClassLoader();
		try {			
		    Class<?> sysclass = URLClassLoader.class;
		    
		    Method method = sysclass.getDeclaredMethod("addURL", URL.class);
		    method.setAccessible(true);
		    method.invoke(ucl, new Object[]{ new File("/home/nwhitehead/hprojects/opentsdb/mavenview/target/opentsdb-2.0.0.jar").toURI().toURL() }); 
			
		} catch (Exception x) {
			x.printStackTrace(System.err);
			throw new RuntimeException(x);
		}		
		
		URL[] urls = ucl.getURLs();
		final String[] cps = new String[urls.length];
		for(int i = 0; i < urls.length; i++) {
			cps[i] = urls[i].toString();
		}
		
		addinClasspaths = cps;
		for(String s: addinClasspaths) {
			log("\tCP:" + s);
		}
		
		addinPackages = EMPTY_ARR;		
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
		if(args==null || args.length==0) return EMPTY_ARR;
		Set<String> set = new LinkedHashSet<String>(args.length);
		for(int i = 0; i < args.length; i++) {
			if(args[i] == null || args[i].trim().isEmpty()) continue;
			set.add(args[i].trim());
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
	
	@RPC
	public class Test {
		
	}

	public static void main(String[] args) {
		try {
			TSDRPCAddinFinder finder = new TSDRPCAddinFinder();
			for(String s: finder.addinClasspaths) {				
				File f = new File(s.trim());
				if(f.exists()) {
					if(f.isDirectory()) {
						finder.scan(f.getAbsoluteFile());
					}
				} else {
					try {
						URL url = new URL(s.trim());
						finder.scan(url);
					} catch (Exception x) {/* No Op */}
				}
			}
		} catch (Exception ex) {
			ex.printStackTrace(System.err);
		}
	}
	
	public static void log(Object msg) {
		System.out.println(msg);
	}
	
	/**
	 * Adds instances of the located RPC handlers to the impl maps
	 * @param clazz The located class
	 */
	protected void processRPCClass(final Class<?> clazz) {
		final RPC rpc = clazz.getAnnotation(RPC.class);
		if(rpc==null) return;
		try {
			String[] names = rpc.httpKeys();
			if(names.length>0 && HttpRpc.class.isAssignableFrom(clazz)) {				
				final HttpRpc httpRpc = (HttpRpc)clazz.newInstance();
				for(final String name: names) {
					if(httpImpls.containsKey(name)) {
						HttpRpc wasHereFirst = httpImpls.get(name); 
						LOG.warn("Configured key {} for HttpRpc {} already allocated for {}", name, clazz.getName(), wasHereFirst.getClass().getName());
					} else {
						httpImpls.put(name, httpRpc);
					}
				}
			}
			names = rpc.telnetKeys();
			if(names.length>0 && TelnetRpc.class.isAssignableFrom(clazz)) {				
				final TelnetRpc telnetRpc = (TelnetRpc)clazz.newInstance();
				for(final String name: names) {
					if(telnetImpls.containsKey(name)) {
						TelnetRpc wasHereFirst = telnetImpls.get(name); 
						LOG.warn("Configured key {} for TelnetRpc {} already allocated for {}", name, clazz.getName(), wasHereFirst.getClass().getName());
					} else {
						telnetImpls.put(name, telnetRpc);
					}
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
			final ClassPath path = new LoaderClassPath(new URLClassLoader(new URL[]{dir.toURI().toURL()})); 
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
								Class<?> instance = ctClazz.toClass();
								LOG.debug("@RPC Match: {}", instance.getName());
								processRPCClass(instance);
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
		final ClassPath path = new LoaderClassPath(new URLClassLoader(new URL[]{url})); 
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
							Class<?> instance = ctClazz.toClass();
							LOG.debug("@RPC Match: {}", instance.getName());
							processRPCClass(instance);
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
