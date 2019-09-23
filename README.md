# ProtoVirt
## (A minimalistic hypervisor)
Ever tought how hypervisor works to provide a virtual enviornment?<br/>
Is hypervisor are complex to create? Yes, they are complex and even more when you are following it though the Intel's developer manual.<br>
To explain this complex process I have started this project to create my own hypervisor in linux. It will help you to understand what minimal VT-X functionality you require as well as what bits to set and what not. <br/>
I have developed it as linux kernel module and continously adding new functionality.

## Usage
Step 1: `make`
<br/>
Step 2: `sudo insmod protovirt.ko`


## Modifications
`guest_code()` is the function that will run after vmlaunch (VM Non-root code). Change it according to your requirement.
Don't forget to update `GUEST_STACK_SIZE` macro for bigger stack for guest.
