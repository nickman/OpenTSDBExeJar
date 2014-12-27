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
import java.lang.ref.WeakReference;
import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javassist.ClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.LoaderClassPath;
import javassist.util.proxy.MethodHandler;
import javassist.util.proxy.ProxyFactory;
import javassist.util.proxy.ProxyObject;

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
	
	/** Annotation Cache */
	protected static final Map<String, WeakReference<? extends Annotation>> annotationCache = new ConcurrentHashMap<String, WeakReference<? extends Annotation>>();
	
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
	
	/**
	 * Executes a full class load on the specified javassist CtClass
	 * @param clazz The javassist CtClass
	 * @return the loaded class
	 */
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
		final Set<String> ignores = new HashSet<String>(128);
		ClassPath path = null; 
		try {
			@SuppressWarnings("resource")
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
							if(isAllowedPackage(ctClazz.getPackageName(), ignores)) { 
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
	
	/**
	 * Retrieves an Annotation proxy of the specified type for the passed class, 
	 * with all scalar and array String attribute values token substituted
	 * @param clazz The class to get the annotation from
	 * @param annotationType The type of annotation to get
	 * @return the annotation proxy
	 */
	@SuppressWarnings("unchecked")
	public <T extends Annotation> T getAnnotation(final Class<?> clazz, final Class<T> annotationType) {
		final String cacheKey = new StringBuilder(clazz.getClassLoader()==null ? "SYS" : clazz.getClassLoader().toString())
		.append("@")
		.append(clazz.getName())
		.append("@")
		.append(annotationType.getName())
		.toString();		
		WeakReference<T> weakRef = (WeakReference<T>) annotationCache.get(cacheKey);
		if(weakRef==null || weakRef.get()==null) {
			synchronized(annotationCache) {
				weakRef = (WeakReference<T>) annotationCache.get(cacheKey);
				if(weakRef==null || weakRef.get()==null) {
					LOG.debug("Building Annotation Proxy [{}@{}]", annotationType.getSimpleName(), clazz.getSimpleName());
					final T t = (T) clazz.getAnnotation((Class<? extends Annotation>)annotationType);
					ProxyFactory pf = new ProxyFactory();
					pf.setInterfaces(new Class[]{((Annotation)t).annotationType()});
					final MethodHandler mi = new MethodHandler() {
						protected final Map<Method, Object> objectCache = new ConcurrentHashMap<Method, Object>();

						public Object invoke(Object self, Method m, Method proceed, Object[] args) throws Throwable {
							try {
								if(!m.isAccessible()) m.setAccessible(true);
								Object value = objectCache.get(m);
								if(value==null) {
									synchronized(objectCache) {
										value = objectCache.get(m);
										if(value==null) {
											LOG.debug("Fetching Annotation Proxy Attribute Value for [{}@{}.({})]", annotationType.getSimpleName(), clazz.getSimpleName(), m.getName());
											if(!m.isAccessible()) m.setAccessible(true);
											value = m.invoke(t);
											final Class<?> mtype = m.getReturnType();
											if(mtype.isArray()) {
												final Class<?> ctype = getBaseType(mtype);
												if(String.class.equals(ctype)) {
													final List<String[]> oneDimArrs = reduce(value, null);
													for(String[] arr: oneDimArrs) {
														for(int i = 0; i < arr.length; i++) {
															arr[i] = tokenReplace(arr[i]);
														}
													}									    			 		    			 
												}
											}
											objectCache.put(m, value);
										}
									}
								}
								return value;
							} catch (Throwable t2) {
								LOG.error("Proxy Invocation Error on [{}]", m.toGenericString(), t2);
								throw t2;
							}
						}
						protected int getDimension(final Class<?> type) {
							int dim = 0;
							Class<?> ctype = type;
							while(ctype.isArray()) {
								dim++;
								ctype = ctype.getComponentType();
							}
							return dim;

						}
						protected Class<?> getBaseType(final Class<?> type) {
							Class<?> ctype = type;
							while(ctype.isArray()) {
								ctype = ctype.getComponentType();
							}
							return ctype;
						}
						protected List<String[]> reduce(final Object arr, final List<String[]> acc) {
							final List<String[]> accumulator = acc==null ? new ArrayList<String[]>() : acc;
							if(!arr.getClass().isArray()) return accumulator;
							final int dim = getDimension(arr.getClass());
							if(dim==1) {
								accumulator.add((String[]) arr);
							} else {
								for(int i = 0; i < dim; i++) {
									reduce(Array.get(arr, i), accumulator);
								}		
							}
							return accumulator;
						}

					};
					try {
						Object obj = pf.createClass().newInstance();
						((ProxyObject)obj).setHandler(mi);
						weakRef = new WeakReference<T>((T)obj);
						annotationCache.put(cacheKey, weakRef);
					} catch (Exception ex) {
						throw new RuntimeException(ex);
					}

				}
			}
		}
		return weakRef.get();
	}
	
	/**
	 * Performs token substitution of the passed string
	 * @param strValue The string to process
	 * @return the token substituted string
	 */
	public String tokenReplace(final String strValue) {
		if(strValue==null || strValue.trim().isEmpty()) return strValue;
		String value = strValue.trim();
		final Matcher m = TOKEN_PATTERN.matcher(value);
		while(m.find()) {
			final String decoded = lookupToken(m.group(1), m.group(2), m.group(3));
			value = value.replace(m.toMatchResult().group() + ":", decoded);
			value = value.replace(m.toMatchResult().group(), decoded);
			
		}
		LOG.debug("Token Subst: [{}] --> [{}]", strValue, value);
		return value;
	}
	
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
	
	
	/** Token pattern for token substitution: g1: token type, g2: the key, g3: the default */
	public static final Pattern TOKEN_PATTERN = Pattern.compile("\\$(.*?)\\{(.*?)(?::(.*?))?\\}");
	
	
	
	
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
		final Set<String> ignores = new HashSet<String>(128);
		BufferedInputStream bis = null;
		JarInputStream jis = null;
		try {
			bis = new BufferedInputStream(is, bufferSize);
			jis = new JarInputStream(bis);
			JarEntry je = null;
			String packageName = null;
			while((je = jis.getNextJarEntry())!=null) {
				if(je.isDirectory()) {
					packageName = je.getName().replace('/', '.');
					while((je = jis.getNextJarEntry())!=null) {
						if(je.isDirectory()) {
							packageName = je.getName().replace('/', '.');
							if(!isAllowedPackage(packageName, ignores)) {
								continue;
							}
						}
					}
					//LOG.info("Directory: [{}]", je.getName());
					continue;
				}
								
				if(!isAllowedPackage(packageName, ignores)) {
					continue;
				}
				if(!je.getName().endsWith(".class")) continue;
				if(packageName!=null) LOG.info("Scanning Archive Directory: [{}]", packageName);
				CtClass ctClazz = classPool.makeClass(jis);
				for(Object ann: ctClazz.getAvailableAnnotations()) {
					if(annotationType.isInstance(ann)) {
						if(isAllowedPackage(ctClazz.getPackageName(), ignores)) { 
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
	 * @param ignores An optional set of known package ignores
	 * @return true if allowed, false otherwise
	 */
	protected boolean isAllowedPackage(final String packageName, final Set<String> ignores) {
		if(packageName==null || packageName.trim().isEmpty() || allowedPackages.isEmpty()) return true;
		if(ignores!=null && ignores.contains(packageName)) return false;
		for(String pname: allowedPackages) {
			if(packageName.indexOf(pname)!=-1) return true;
		}
		if(ignores!=null) ignores.add(packageName);
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
		AnnotationFinder af = new AnnotationFinder(true);
		af.appendAllowedPackages("net.opentsdb.utils");
		LOG.info("Testing AnnotationFinder");
		
		Collection<Class<?>> classes = af.scan(net.opentsdb.tsd.RPC.class);
		LOG.info("Loaded Classes:" + classes.size());
		for(int i = 0; i < 10; i++) {
			for(Class<?> klazz: classes) {
				net.opentsdb.tsd.RPC rpc = af.getAnnotation(klazz, net.opentsdb.tsd.RPC.class);
						//klazz.getAnnotation(RPC.class);
				LOG.info(String.format("Class: [%s], httpKeys: %s", klazz.getName(), Arrays.toString(rpc.httpKeys())));
			}
		}
	}

	@net.opentsdb.tsd.RPC(httpKeys={"$s{java.io.tmpdir}", "$e{USER}"})
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
}
