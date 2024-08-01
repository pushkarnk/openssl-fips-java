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
package com.canonical.openssl.cipher;

final public class AES__KS__with__MODE__padding__PADC__ extends CipherAes {

    public AES__KS__with__MODE__padding__PADC__() {
        super("AES-__KS__-__MODE__", "__PAD__");
    }

    @Override
    public int getKeySize() {
        return __KS__;
    }

    @Override
    public String getMode() {
        return "__MODE__";
    }

    @Override
    public String getPadding() {
        return "__PAD__";
    }
}

 
    
