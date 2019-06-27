/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2019 John H. Baldwin <jhb@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#ifndef __CONFIG_H__
#define	__CONFIG_H__

#include <sys/nv.h>

/*-
 * Manages a configuration database backed by an nv(9) list.
 *
 * The database only stores string values.  Callers should parse
 * values into other types if needed.  String values can reference
 * other configuration variables using a '%(name)' syntax.  In this
 * case, the name must be the the full path of the configuration
 * variable.  The % character can be escaped with a preceding \ to
 * avoid expansion.  Any \ characters must be escaped.
 *
 * Configuration variables are stored in a tree.  The full path of a
 * variable is specified as a dot-separated name similar to sysctl(8)
 * OIDs.
 */ 

/*
 * Fetches the value of a configuration variable.  If the "raw" value
 * contains references to other configuration variables, this function
 * expands those references and returns a pointer to the parsed
 * string.  The string's storage is only stable until the next call to
 * this function.
 *
 * If no node is found, returns NULL.
 *
 * If 'parent' is NULL, 'name' is assumed to be a top-level variable.
 */
const char *get_config_value(nvlist_t *parent, const char *name);

/*
 * Similar to get_config_value but expects a full path to the leaf
 * node.
 */
const char *get_config_value_path(const char *path);

/*
 * Fetches a config value and interprets it as a boolean.
 */
bool get_config_bool_path(const char *path);

/* Initializes the tree to an empty state. */
void	init_config(void);

/*
 * Parses a dot-separated OID path.  Will fail if the path names an
 * existing leaf configuration variable.  Will create a new node if it
 * does not yet exist and 'create' is true.
 */
nvlist_t *lookup_config_node(const char *path, bool create);

/*
 * Adds or replaces the value of the specified variable.
 *
 * If 'parent' is NULL, 'name' is assumed to be a top-level variable.
 */
void	set_config_value(nvlist_t *parent, const char *name,
    const char *value);

/*
 * Similar to add_config_node but expects a full path to the leaf
 * node.
 */
void	set_config_value_path(const char *path, const char *value);

/*
 * Sets a configuration variable to "true" or "false".
 */
void	set_config_bool(const char *path, bool value);

void	dump_config(void);

#endif /* !__CONFIG_H__ */
