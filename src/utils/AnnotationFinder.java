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

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.annotation.Annotation;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javassist.ClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.LoaderClassPath;
import javassist.bytecode.annotation.AnnotationMemberValue;
import javassist.bytecode.annotation.ArrayMemberValue;
import javassist.bytecode.annotation.BooleanMemberValue;
import javassist.bytecode.annotation.ByteMemberValue;
import javassist.bytecode.annotation.CharMemberValue;
import javassist.bytecode.annotation.ClassMemberValue;
import javassist.bytecode.annotation.DoubleMemberValue;
import javassist.bytecode.annotation.EnumMemberValue;
import javassist.bytecode.annotation.FloatMemberValue;
import javassist.bytecode.annotation.IntegerMemberValue;
import javassist.bytecode.annotation.LongMemberValue;
import javassist.bytecode.annotation.MemberValue;
import javassist.bytecode.annotation.MemberValueVisitor;
import javassist.bytecode.annotation.ShortMemberValue;
import javassist.bytecode.annotation.StringMemberValue;
import javassist.util.proxy.MethodHandler;
import javassist.util.proxy.ProxyFactory;
import javassist.util.proxy.ProxyObject;
import net.opentsdb.tsd.RPC;

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
	
	/** The configured attribute decoder maps */
	protected final Map<String, Map<String, String>> attributeDecoders = new HashMap<String, Map<String, String>>();
	/** The final de-dupped anf fully normalized classpath to scan */
	protected final Set<URL> finalPaths = new LinkedHashSet<URL>();
	/** A set of package names that are included */
	protected final Set<String> allowedPackages = new HashSet<String>();
	/** The JVM system properties as a string map */
	protected final Map<String, String> SYSPROPS_AS_MAP = new HashMap<String, String>(System.getProperties().size());
	
	/** The JAR file extension */
	public static final String JAR_EXT = ".jar";
	/** The ZIP file extension */
	public static final String ZIP_EXT = ".zip";
	
	/** The default buffer size for buffered streams */
	public static final int DEFAULT_BUFFER_SIZE = 20480;
	
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
		attributeDecoders.put("s", getSysPropsMap());
		attributeDecoders.put("e", System.getenv());
	}
	
	
	/**
	 * Adds a new decoder map for filling in tokens in annotation attributes with substitution tokens
	 * @param key The map key
	 * @param decodes The map
	 * @return this finder
	 */
	public AnnotationFinder addAttributeDecoderMap(final String key, final Map<String, String> decodes) {
		if(key==null || key.trim().isEmpty()) throw new IllegalArgumentException("The passed key was null or empty");
		if(attributeDecoders.containsKey(key)) throw new IllegalArgumentException("The attributeDecoder map for type [" + key + "] is already registered");
		if(decodes==null) throw new IllegalArgumentException("The passed decode map was null");
		attributeDecoders.put(key, decodes);
		return this;
	}
	
	public static void log(Object msg) {
		System.out.println(msg);
	}
	
	/**
	 * Executes the scan and returns all the located classes
	 * @param annotationType The type level annotation to scan for
	 * @return a collection of all the classes located
	 */
	public Collection<Class<?>> scan(final Class<? extends Annotation> annotationType) {
		final Map<String, Class<?>> foundClasses = new HashMap<String, Class<?>>();
		final Map<String, CtClass> ctClasses = new HashMap<String, CtClass>();
		if(!finalPaths.isEmpty()) {
			for(final URL url: finalPaths) {
				final Map<String, CtClass> located;
				if("file".equals(url.getProtocol())) {
					try {
						File f = new File(url.toURI());
						located = f.isDirectory() ? scanDir(f, annotationType) : scanArchive(f, annotationType);
					} catch (URISyntaxException e) {
						LOG.warn("Unexpected failure to get File from URL [{}]", url);
						continue;
					}					
				} else {
					located = scanUrl(url, annotationType);
				}
				if(located.isEmpty()) continue;
				for(Map.Entry<String, CtClass> entry: located.entrySet()) {
					if(!ctClasses.containsKey(entry.getKey())) {
						ctClasses.put(entry.getKey(), entry.getValue());
					}
				}
			}
			for(Map.Entry<String, CtClass> entry: ctClasses.entrySet()) {
				if(!foundClasses.containsKey(entry.getKey())) {					
					foundClasses.put(entry.getKey(), loadClass(entry.getValue()));
				}				
			}
		} else {
			LOG.warn("No configured paths to scan fr annotation [{}]", annotationType.getName());
		}
		return foundClasses.values();
	}
	
	protected Class<?> loadClass(final CtClass clazz) {
		try {
			return Class.forName(clazz.getName());
		} catch (Throwable t) {
			try {
				return Class.forName(clazz.getName(), true, classPool.getClassLoader());
			} catch (Throwable t2) {
				try {
					return clazz.toClass();
				} catch (Throwable t3) {
					LOG.error("Failed to load class [{}]", clazz.getName(), t);
					LOG.error("Failed to load class [{}]", clazz.getName(), t2);
					LOG.error("Failed to load class [{}]", clazz.getName(), t3);
					return null;
				}
			}
		}
	}
	
	
	/**
	 * Scans the passed URL for classes annotated with the passed annotation type
	 * @param url The archive URL to scan
	 * @param annotationType The target annotation type
	 * @return a Map of javassist class representations keyed by the class name
	 */
	protected Map<String, CtClass> scanUrl(final URL url, final Class<? extends Annotation> annotationType) {
		InputStream is = null;
		try {
			is = url.openStream();
			int avail = is.available();
			if(avail < DEFAULT_BUFFER_SIZE) avail = DEFAULT_BUFFER_SIZE;
			return scan(avail, is, annotationType);
		} catch (Exception ex) {
			LOG.warn("Failed to scan URL [{}]", url, ex);
			return Collections.emptyMap();
		} finally {
			if(is!=null) try { is.close(); } catch (Exception x) {/* No Op */}
		}		
	}
	
	/**
	 * Scans the passed directory for classes annotated with the passed annotation type
	 * @param dir The directory to scan
	 * @param annotationType The target annotation type
	 * @return a Map of javassist class representations keyed by the class name
	 */
	protected Map<String, CtClass> scanDir(final File dir, final Class<? extends Annotation> annotationType) {
		final Map<String, CtClass> classMap = new HashMap<String, CtClass>();
		ClassPath path = null; 
		try {
			final ClassLoader CL = new URLClassLoader(new URL[]{dir.toURI().toURL()});
			path = new LoaderClassPath(CL); 
			classPool.appendClassPath(path);
			final Set<File> classFiles = findClassFiles(dir, null);
			for(final File f: classFiles) {
				FileInputStream fis = null;
				try {
					fis = new FileInputStream(f);
					CtClass ctClazz = classPool.makeClass(fis);
					for(Object ann: ctClazz.getAvailableAnnotations()) {
						if(annotationType.isInstance(ann)) {
							if(isAllowedPackage(ctClazz.getPackageName())) {
								if(!classMap.containsKey(ctClazz.getName())) {
									classMap.put(ctClazz.getName(), ctClazz);
								}															
							}
							break;
						}
					}
				} finally {
					if(fis!=null) try { fis.close(); } catch (Exception x) {/* No Op */}
				}
			}
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}				
		return classMap;
	}
	
	public <T> T getAnnotation(final Class<?> clazz, final Class<T> annotationType) {
		final T t = (T) clazz.getAnnotation((Class<? extends Annotation>)annotationType);
		ProxyFactory pf = new ProxyFactory();
		pf.setInterfaces(new Class[]{((Annotation)t).annotationType()});
		MethodHandler mi = new MethodHandler() {
		     public Object invoke(Object self, Method m, Method proceed, Object[] args) throws Throwable {
		    	 return null;
		     }
		};
		try {
			Object obj = pf.createClass().newInstance();
			((ProxyObject)obj).setHandler(mi);
			return (T)obj;
		} catch (Exception ex) {
			throw new RuntimeException(ex);
		}
	}
	
	/** Token pattern for token substitution: g1: token type, g2: the key, g3: the default */
	public static final Pattern TOKEN_PATTERN = Pattern.compile("\\$(.*?)\\{(.*?)(?::(.*?))?\\}");
	
	
	private final MemberValueVisitor memberDecoder = new EmptyMemberValueVisitor() {
		/**
		 * {@inheritDoc}
		 * @see net.opentsdb.utils.AnnotationFinder.EmptyMemberValueVisitor#visitArrayMemberValue(javassist.bytecode.annotation.ArrayMemberValue)
		 */
		@Override
		public void visitArrayMemberValue(final ArrayMemberValue node) {
			if(node!=null && node.getValue()!=null) {
				for(final MemberValue mv: node.getValue()) {
					if(mv!=null) mv.accept(this);
				}
			}
		}
		
		/**
		 * {@inheritDoc}
		 * @see net.opentsdb.utils.AnnotationFinder.EmptyMemberValueVisitor#visitStringMemberValue(javassist.bytecode.annotation.StringMemberValue)
		 */
		@Override
		public void visitStringMemberValue(final StringMemberValue node) {
			if(node!=null && node.getValue()!=null) {
				String value = node.getValue();
				if(value!=null) {
//					final StringBuffer b = new StringBuffer();
					final Matcher m = TOKEN_PATTERN.matcher(value);
					while(m.find()) {
						final String decoded = lookupToken(m.group(1), m.group(2), m.group(3));
						value = value.replace(m.toMatchResult().group(), decoded);
						
					}
//					m.appendTail(b);
					node.setValue(value);
				}
			}
		}
		
//		public T getAnnotation(final Class<?> clazz, final Class<T extends Annotation> annotationType) {
//			Annotation tAnn = clazz.getAnnotation(annotationType);
//			return Proxy.newProxyInstance(clazz.getClassLoader(), new Class[]{tAnn.annotationType()}, new InvocationHandler() {
//				/**
//				 * {@inheritDoc}
//				 * @see java.lang.reflect.InvocationHandler#invoke(java.lang.Object, java.lang.reflect.Method, java.lang.Object[])
//				 */
//				@Override
//				public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
//					// TODO Auto-generated method stub
//					return null;
//				}
//			});
//		}
		
		/**
		 * Attempts to decode this token 
		 * @param type The type of the token
		 * @param key The token key
		 * @param defaultValue The default
		 * @return the decoded value or the default
		 */
		public String lookupToken(final String type, final String key, final String defaultValue) {
			final String def = defaultValue==null ? "" : defaultValue;
			if(type==null || type.trim().isEmpty()) return def;
			if(key==null || key.trim().isEmpty()) return def;
			final Map<String, String> dmap = attributeDecoders.get(type.trim());
			if(dmap==null) return def;
			final String val = dmap.get(key.trim());
			return val==null ? def : val.trim();
		}
	};
	
	
	
	/**
	 * Recursive directory scanner to find class file
	 * @param dir The directory to scan
	 * @param acc The accumulated file set
	 * @return The located class files
	 */
	protected static Set<File> findClassFiles(final File dir, final Set<File> acc) {
		final Set<File> accum = acc==null ?  new LinkedHashSet<File>() : acc;
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
	
	
	/**
	 * Scans the passed archive file for classes annotated with the passed annotation type
	 * @param archive The archive to scan
	 * @param annotationType The target annotation type
	 * @return a Map of javassist class representations keyed by the class name
	 */
	protected Map<String, CtClass> scanArchive(final File archive, final Class<? extends Annotation> annotationType) {
		InputStream is = null;
		try {
			is = new FileInputStream(archive);
			return scan((int)archive.length(), is, annotationType);
		} catch (Exception ex) {
			LOG.warn("Failed to scan Archive File [{}]", archive.getAbsolutePath(), ex);
			return Collections.emptyMap();
		} finally {
			if(is!=null) try { is.close(); } catch (Exception x) {/* No Op */}
		}
	}
	
	/**
	 * Scans the passed input stream for classes annotated with the passed annotation type
	 * @param bufferSize The byte size of the buffered input stream buffer
	 * @param is The input stream to scan
	 * @param annotationType The target annotation type
	 * @return a Map of javassist class representations keyed by the class name
	 * @throws IOException Thrown on any IO errors
	 */
	protected Map<String, CtClass> scan(final int bufferSize, final InputStream is, final Class<? extends Annotation> annotationType) throws IOException {
		final Map<String, CtClass> classMap = new HashMap<String, CtClass>();
		BufferedInputStream bis = null;
		JarInputStream jis = null;
		try {
			bis = new BufferedInputStream(is, bufferSize);
			jis = new JarInputStream(bis);
			JarEntry je = null;
			while((je = jis.getNextJarEntry())!=null) {
				if(je.isDirectory() || !je.getName().endsWith(".class")) continue;
				CtClass ctClazz = classPool.makeClass(jis);
				for(Object ann: ctClazz.getAvailableAnnotations()) {
					if(annotationType.isInstance(ann)) {
						if(isAllowedPackage(ctClazz.getPackageName())) {
							if(!classMap.containsKey(ctClazz.getName())) {
								classMap.put(ctClazz.getName(), ctClazz);
							}							
						}
						break;
					}
				}
			}			
		} finally {
			if(bis!=null) try { bis.close(); } catch (Exception x) {/* No Op */}
			if(jis!=null) try { jis.close(); } catch (Exception x) {/* No Op */}
		}
		return classMap;		
	}
	
	
	
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
	 * Adds the passed package names to the allowed package name list.
	 * If any are defined, only classes within the defined packages will be returned on the next scan.
	 * If none are defined, no package name restrictions will be implemented.
	 * @param packageNames The package names to add
	 * @return this finder
	 */
	public AnnotationFinder appendAllowedPackages(final String...packageNames) {
		if(packageNames!=null && packageNames.length>0) {
			for(String s: packageNames) {
				if(s==null || s.trim().isEmpty()) continue;
				allowedPackages.add(s.trim());
			}
		}
		return this;
	}
	
	/**
	 * Determines if the passed package name is in an allowed package
	 * @param packageName The package name to test
	 * @return true if allowed, false otherwise
	 */
	protected boolean isAllowedPackage(final String packageName) {
		if(allowedPackages.isEmpty()) return true;
		for(String pname: allowedPackages) {
			if(packageName.indexOf(pname)!=-1) return true;
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
	
	/**
	 * Quickie CL test
	 * @param args None
	 */
	public static void main(String[] args) {
		System.out.println(new AnnotationFinder(true).printPath());
		log("Testing AnnotationFinder");
		AnnotationFinder af = new AnnotationFinder(true);
		Collection<Class<?>> classes = af.scan(RPC.class);
		log("Loaded Classes:" + classes.size());
		for(Class<?> klazz: classes) {
			RPC rpc = klazz.getAnnotation(RPC.class);
			log(String.format("Class: [%s], httpKeys: %s", klazz.getName(), Arrays.toString(rpc.httpKeys())));
		}
	}

	@RPC(httpKeys={"$s{java.io.tmpdir}", "$e{COMPUTERNAME}"})
	private static class Foo {
		
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
		LOG.debug("Located [{}] System ClassLoader URL Classpath Entries", urls.length);
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
	
	/**
	 * Returns the system prop string map, populating it if it was not already
	 * @return the system prop string map
	 */
	private Map<String, String> getSysPropsMap() {
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
	
	
	private class EmptyMemberValueVisitor implements MemberValueVisitor {

		/**
		 * {@inheritDoc}
		 * @see javassist.bytecode.annotation.MemberValueVisitor#visitAnnotationMemberValue(javassist.bytecode.annotation.AnnotationMemberValue)
		 */
		@Override
		public void visitAnnotationMemberValue(AnnotationMemberValue node) {
			/* No Op */
		}

		/**
		 * {@inheritDoc}
		 * @see javassist.bytecode.annotation.MemberValueVisitor#visitArrayMemberValue(javassist.bytecode.annotation.ArrayMemberValue)
		 */
		@Override
		public void visitArrayMemberValue(ArrayMemberValue node) {
			/* No Op */
		}

		/**
		 * {@inheritDoc}
		 * @see javassist.bytecode.annotation.MemberValueVisitor#visitBooleanMemberValue(javassist.bytecode.annotation.BooleanMemberValue)
		 */
		@Override
		public void visitBooleanMemberValue(BooleanMemberValue node) {
			/* No Op */
		}

		/**
		 * {@inheritDoc}
		 * @see javassist.bytecode.annotation.MemberValueVisitor#visitByteMemberValue(javassist.bytecode.annotation.ByteMemberValue)
		 */
		@Override
		public void visitByteMemberValue(ByteMemberValue node) {
			/* No Op */			
		}

		/**
		 * {@inheritDoc}
		 * @see javassist.bytecode.annotation.MemberValueVisitor#visitCharMemberValue(javassist.bytecode.annotation.CharMemberValue)
		 */
		@Override
		public void visitCharMemberValue(CharMemberValue node) {
			/* No Op */			
		}

		/**
		 * {@inheritDoc}
		 * @see javassist.bytecode.annotation.MemberValueVisitor#visitDoubleMemberValue(javassist.bytecode.annotation.DoubleMemberValue)
		 */
		@Override
		public void visitDoubleMemberValue(DoubleMemberValue node) {
			/* No Op */
		}

		/**
		 * {@inheritDoc}
		 * @see javassist.bytecode.annotation.MemberValueVisitor#visitEnumMemberValue(javassist.bytecode.annotation.EnumMemberValue)
		 */
		@Override
		public void visitEnumMemberValue(EnumMemberValue node) {
			/* No Op */
		}

		/**
		 * {@inheritDoc}
		 * @see javassist.bytecode.annotation.MemberValueVisitor#visitFloatMemberValue(javassist.bytecode.annotation.FloatMemberValue)
		 */
		@Override
		public void visitFloatMemberValue(FloatMemberValue node) {
			/* No Op */
		}

		/**
		 * {@inheritDoc}
		 * @see javassist.bytecode.annotation.MemberValueVisitor#visitIntegerMemberValue(javassist.bytecode.annotation.IntegerMemberValue)
		 */
		@Override
		public void visitIntegerMemberValue(IntegerMemberValue node) {
			/* No Op */			
		}

		/**
		 * {@inheritDoc}
		 * @see javassist.bytecode.annotation.MemberValueVisitor#visitLongMemberValue(javassist.bytecode.annotation.LongMemberValue)
		 */
		@Override
		public void visitLongMemberValue(LongMemberValue node) {
			/* No Op */
		}

		/**
		 * {@inheritDoc}
		 * @see javassist.bytecode.annotation.MemberValueVisitor#visitShortMemberValue(javassist.bytecode.annotation.ShortMemberValue)
		 */
		@Override
		public void visitShortMemberValue(ShortMemberValue node) {
			/* No Op */
		}

		/**
		 * {@inheritDoc}
		 * @see javassist.bytecode.annotation.MemberValueVisitor#visitStringMemberValue(javassist.bytecode.annotation.StringMemberValue)
		 */
		@Override
		public void visitStringMemberValue(StringMemberValue node) {
			/* No Op */
		}

		/**
		 * {@inheritDoc}
		 * @see javassist.bytecode.annotation.MemberValueVisitor#visitClassMemberValue(javassist.bytecode.annotation.ClassMemberValue)
		 */
		@Override
		public void visitClassMemberValue(ClassMemberValue node) {
			/* No Op */
		}
		
	}

}
