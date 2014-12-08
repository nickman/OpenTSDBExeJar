// This file is part of OpenTSDB.
// Copyright (C) 2010-2014  The OpenTSDB Authors.
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
package net.opentsdb.utils;

import java.io.File;
import java.lang.management.ManagementFactory;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

import javassist.ClassPool;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * <p>Title: AnnotationFinder</p>
 * <p>Description: Utility class to find annotated classes and methods</p> 
 * <p>Company: Helios Development Group LLC</p>
 * @author Whitehead (nwhitehead AT heliosdev DOT org)
 * <p><code>net.opentsdb.utils.AnnotationFinder</code></p>
 */
public class AnnotationFinder {
	/** Static class logger */
	private static final Logger LOG = LoggerFactory.getLogger(AnnotationFinder.class);
	
	
	/** The final de-dupped anf fully normalized classpath to scan */
	protected final Set<URL> finalPaths = new LinkedHashSet<URL>();
	
	/** The JAR file extension */
	public static final String JAR_EXT = ".jar";
	/** The ZIP file extension */
	public static final String ZIP_EXT = ".zip";
	
	/** Extensions of files or URLs that can be loaded */
	public static final Set<String> LOADABLE_EXTENSIONS = Collections.unmodifiableSet(new HashSet<String>(Arrays.asList(
		JAR_EXT, ZIP_EXT
	)));
	
	/*
	 * Each entry will be one of:
	 * 	A file ref to a dir
	 *  A file ref to a Jar
	 *  A non-file URL to a Jar
	 */
	
	/** The javassist classpool to read class meta-data with */
	protected final ClassPool classPool;
	
	/**
	 * Creates a new AnnotationFinder
	 * @param includeDefaultClasspath If true, will scan the default classpath, otherwise only scans appended resources.
	 * The default classpath is determined by
	 * the JVM Runtime's classpath array, plus the URLClassLoaders defined in {@link ClassLoader#getSystemClassLoader()}
	 */
	public AnnotationFinder(final boolean includeDefaultClasspath) {
		classPool = new ClassPool(true);
		if(includeDefaultClasspath) {
			for(String path: gatherDefaultClasspath()) {
				URL url = toURL(path);
				if(url!=null) {
					finalPaths.add(url);
				}
			}
			LOG.debug("Added [{}] default classpath URLs", finalPaths.size());
		}
	}
	
	//public Set<Class<?>> 
	
	/**
	 * Converts the passed file to a URL
	 * @param file The file to convert
	 * @return The converted URL or null if the file did not exist
	 */
	public static URL toURL(final File file) {
		if(file==null || !file.exists()) return null;
		try {
			return file.toURI().toURL();
		} catch (MalformedURLException e) {
			return null;
		}
	}
	
	/**
	 * Creates a URL from the passed path
	 * @param path The path to convert
	 * @return the URL or null if the path could not be converted or represents
	 * a resource that cannot be read as a classpath
	 */
	public static URL toURL(final String path) {
		if(path==null || path.trim().isEmpty()) return null;
		try {
			// File must exist and be either a directory or a *.jar file
			File file = new File(path.trim());
			if(file.exists() && (file.isDirectory() || file.getName().toLowerCase().endsWith(JAR_EXT))) {
				return file.getAbsoluteFile().toURI().toURL();
			}			
			URL url = new URL(path.trim());
			// URL could also be a file
			if("file".equals(url.getProtocol())) {
				file = new File(url.getFile().trim());
				if(file.exists() && (file.isDirectory() || file.getName().toLowerCase().endsWith(JAR_EXT))) {
					return file.getAbsoluteFile().toURI().toURL();
				}		
				return null;
			}
			// Non-file URL must have a loadable extension
			if(isLoadableExtension(url)) return url;
			return null;
		} catch (Exception ex) {
			LOG.warn("Failed to URL convert path [{}]", path);
			return null;
		}
	}
	
	/**
	 * Indicates if the file extension of the passed URL is class-loadable 
	 * @param url The URL to test
	 * @return true if loadable, false otherwise
	 */
	public static boolean isLoadableExtension(final URL url) {
		if(url==null) return false;
		String urlFile = url.getFile();
		if(urlFile!=null && !urlFile.trim().isEmpty()) {
			final String fileName = urlFile.trim().toLowerCase();
			for(final String ext: LOADABLE_EXTENSIONS) {
				if(fileName.endsWith(ext)) return true;
			}
		}
		return false;
	}
	
	/**
	 * Indicates if the extension of the passed File is class-loadable 
	 * @param file The File to test
	 * @return true if loadable, false otherwise
	 */
	public static boolean isLoadableExtension(final File file) {
		if(file==null) return false;
		final String fileName = file.getName().trim().toLowerCase();
		if(fileName!=null && !fileName.trim().isEmpty()) {
			for(final String ext: LOADABLE_EXTENSIONS) {
				if(fileName.endsWith(ext)) return true;
			}
		}
		return false;		
	}
	
	
	
	/**
	 * Appends an array of files to scan
	 * @param files The array of files to add
	 * @return this finder
	 */
	public AnnotationFinder appendPaths(final File...files) {
		int d = 0, f = 0;
		if(files!=null && files.length>0) {
			for(File file: files) {
				if(file==null) continue;
				if(file.exists()) {
					file = file.getAbsoluteFile();
					if(file.isDirectory()) {
						URL url = toURL(file);
						if(url!=null) {
							if(finalPaths.add(url)) d++;
						}						
					} else {
						if(isLoadableExtension(file)) {
							URL url = toURL(file);
							if(url!=null) {
								if(finalPaths.add(url)) f++;
							}													
						} else {
							LOG.warn("Added file [{}] not directory or Jar. Discarding.", file.getAbsolutePath());
						}
					}
				}
			}
		}
		LOG.debug("Added [{}] JAR files and [{}] class directories", f, d);
		return this;
	}
	
	/**
	 * Appends an array of URLs to scan
	 * @param urls The array of URLs to add
	 * @return this finder
	 */
	public AnnotationFinder appendPaths(final URL...urls) {
		int u = 0;
		if(urls!=null && urls.length>0) {
			for(URL url: urls) {
				if(url==null) continue;
				if("file".equals(url.getProtocol())) {
					try {
						File f = new File(url.toURI());
						if(f.exists() && (f.isDirectory() || isLoadableExtension(f))) {
							if(finalPaths.add(toURL(f.getAbsoluteFile()))) u++;
						}
					} catch (Exception ex) {/* No Op */}					
				} else {
					if(isLoadableExtension(url)) {
						if(url!=null) {
							if(finalPaths.add(url)) u++;
						}																			
					}
				}
			}
		}
		LOG.debug("Added [{}] URLs", u);
		return this;
	}
	
	/**
	 * Appends an array of untyped string paths to scan
	 * @param paths The array of paths to add
	 * @return this finder
	 */
	public AnnotationFinder appendPaths(final String...paths) {
		if(paths!=null && paths.length>0) {
			for(String path: paths) {
				if(path==null || path.trim().isEmpty()) continue;
				path = path.trim();
				File f = new File(path);
				if(f.exists()) {
					f = f.getAbsoluteFile();
					appendPaths(f);
				} else {
					URL url = toURL(path);
					if(url!=null) {
						appendPaths(url);
					}
				}
			}
		}
		return this;
	}
	
	/**
	 * Returns a formatted report of the paths that will be scanned by this annotation finder
	 * @return a list of paths to be scanned
	 */
	public String printPath() {
		if(finalPaths.isEmpty()) return "";
		StringBuilder b = new StringBuilder("\n\t==============================\n\tAnnotationFinder Classpath\n\t==============================");
		for(URL url: finalPaths) {
			b.append("\n\t").append(url);
		}
		return b.append("\n\t==============================\n").toString();
	}
	
	public static void main(String[] args) {
		System.out.println(new AnnotationFinder(true).printPath());
	}

	/**
	 * Creates an array of URL and File based classpath entries that should be searched for annotated classes
	 * @return an array of URL and File based classpath entries
	 */
	@SuppressWarnings("resource")
	protected String[] gatherDefaultClasspath() {
		final Set<File> fpaths = new LinkedHashSet<File>();
		final Set<String> paths = new LinkedHashSet<String>();
		for(String s: ManagementFactory.getRuntimeMXBean().getClassPath().split(File.pathSeparator)) {
			File f = new File(s);
			if(f.exists()) {
				fpaths.add(f.getAbsoluteFile());
			}
			paths.add(s);
		}
		LOG.debug("Located [{}] Runtime Classpath Entries", paths.size());
		// Get the system class loader URLs, since the TSDB forces classpath changes by adding URLS
		// directly to the URLClassLoader, so they don't show up in the RuntimeMXBean
		URLClassLoader ucl = (URLClassLoader)ClassLoader.getSystemClassLoader();
		URL[] urls = ucl.getURLs();
		LOG.debug("Located [{}] System ClassLoader URL Classpath Entries", urls==null ? 0 : urls.length);
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
		LOG.debug("Located [{}] Total Classpath Entries", paths.size());
		return paths.toArray(new String[paths.size()]);
	}
	

}
