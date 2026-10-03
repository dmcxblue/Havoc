# Havoc Teamserver

Source code of Havoc teamserver. Written in Golang.


### Build the Teamserver
- **Pre-requisites**
	1. Go1.18
- **Native**
	- To build the Teamserver client locally, run the following command in this folder(`~/Havoc/Teamserver/`):
		1. `make`
	- That's it! If it ran successfully to completion, you should now have a compiled binary ready for use in the `/bin` folder.
	- Example use with a prewritten profile: `sudo ./teamserver server --profile profiles/havoc.yaotl --verbose`
	- Example use with default profile: `sudo ./teamserver --default --verbose`


### Run the Teamserver
- **Base:**
	- The teamserver can also be used directly:
		* `./teamserver -h`
		* `./teamserver server --profile profiles/havoc.yaotl -v`
		* `./teamserver server --default -v`
