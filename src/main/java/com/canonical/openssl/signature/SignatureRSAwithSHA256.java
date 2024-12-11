/*
 * Copyright (C) Canonical, Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
package com.canonical.openssl.signature;

public final class SignatureRSAwithSHA256 extends OpenSSLSignature {

    public SignatureRSAwithSHA256() {
        super(new OpenSSLSignature.Params("SHA-256", -1, OpenSSLSignature.Padding.NONE, null));
    }

    protected String getSignatureName() {
        return "RSAwithSHA256";
    }
}
