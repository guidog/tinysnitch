# This file is part of tinysnitch, formerly known as OpenSnitch.
#
# Copyright(c) 2019 Nathan Todd-Stone
# me@nathants.com
# https://nathants.com
#
# This file may be licensed under the terms of of the
# GNU General Public License Version 2 (the ``GPL'').
#
# Software distributed under the License is distributed
# on an ``AS IS'' basis, WITHOUT WARRANTY OF ANY KIND, either
# express or implied. See the GPL for the specific language
# governing rights and limitations.
#
# You should have received a copy of the GPL along with this
# program. If not, go to http://www.gnu.org/licenses/gpl.html
# or write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

import tinysnitch.lib
import tinysnitch.netfilter

assert tinysnitch.lib.check_output('whoami') == 'root', 'tinysnitchd must run as root'

def main():
    nfq_handle, nfq_q_handle = tinysnitch.netfilter.create()
    try:
        nfq_fd = tinysnitch.netfilter.setup(nfq_handle, nfq_q_handle)
        tinysnitch.netfilter.run(nfq_handle, nfq_fd)
    except KeyboardInterrupt:
        pass
    finally:
        tinysnitch.netfilter.destroy(nfq_q_handle, nfq_handle)
