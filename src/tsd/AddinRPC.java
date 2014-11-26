/**
 * Helios, OpenSource Monitoring
 * Brought to you by the Helios Development Group
 *
 * Copyright 2014, Helios Development Group and individual contributors
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

/**
 * <p>Title: AddinRPC</p>
 * <p>Description: A wrapper for RPC Addins</p> 
 * <p>Company: Helios Development Group LLC</p>
 * @author Whitehead (nwhitehead AT heliosdev DOT org)
 * <p><code>net.opentsdb.tsd.AddinRPC</code></p>
 */

public interface AddinRPC {
	/**
	 * Indicates if this RPC is an {@link HttpRpc}
	 * @return true if this RPC is an {@link HttpRpc}, false otherwise
	 */
	public boolean isHttpRpc();
	/**
	 * Indicates if this RPC is a {@link TelnetRpc}
	 * @return true if this RPC is an {@link TelnetRpc}, false otherwise
	 */
	public boolean isTelnetRpc();
	/**
	 * Returns the {@link HttpRpc} instance.
	 * Throws an {@link IllegalStateException} if {@link #isHttpRpc()} returns false.
	 * @return  a {@link HttpRpc}
	 */
	public HttpRpc getHttpRpc();
	/**
	 * Returns the {@link TelnetRpc} instance.
	 * Throws an {@link IllegalStateException} if {@link #isTelnetRpc()} returns false.
	 * @return  a {@link TelnetRpc}
	 */
	public TelnetRpc getTelnetRpc();
	/**
	 * Returns the RPC key for the {@link HttpRpc}.
	 * Throws an {@link IllegalStateException} if {@link #isHttpRpc()} returns false.
	 * @return the RPC key for the {@link HttpRpc} 
	 */
	public String getHttpKey();
	/**
	 * Returns the RPC key for the {@link TelnetRpc}.
	 * Throws an {@link IllegalStateException} if {@link #isTelnetRpc()} returns false.
	 * @return the RPC key for the {@link TelnetRpc} 
	 */
	public String getTelnetKey();
}
