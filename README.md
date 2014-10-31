# _check_zonesync_

_check_zonesync is a check which can determine whether zone are replicated pro-
perly between master and slave DNS servers.

## Project Setup

In order to run check_zonesync you need to following dependencies installed:
- pymisc (https://github.com/vespian/pymisc)
- python >=3.2 (not tested on earlier versions)
- python3-yaml
- python3-dnspython

You can also use debian packaging rules from debian/ directory to build a deb
package.


WARNING!

This is work in progress, YMMV!

FIXME:
 - unittests
 - documentation
