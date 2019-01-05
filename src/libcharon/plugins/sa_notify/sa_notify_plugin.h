/*
 * Copyright (C) 2018 Christopher Chon
 * Nefeli Networks Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/**
 * @defgroup sa_notify sa_notify
 * @ingroup cplugins
 *
 * @defgroup sa_notify_plugin sa_notify_plugin
 * @{ @ingroup sa_notify
 */

#ifndef SA_NOTIFY_PLUGIN_H_
#define SA_NOTIFY_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct sa_notify_plugin_t sa_notify_plugin_t;

/**
 * Plugin that writes IKEv2 and CHILD SA creation, rekeying, and deletion to a
 * file.
 */
struct sa_notify_plugin_t {

	/**
	 * Implements plugin_t interface.
	 */
	plugin_t plugin;
};

#endif /** SA_NOTIFY_PLUGIN_H_ @} */
