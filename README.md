# ProtoVirt
## (A minimalistic hypervisor)
Ever thought how hypervisor works to provide a virtual enviornment?<br/>
Are hypervisor complex to create? <br/>
Yes, they are complex and even more when you are following Intel's developer manual for this.<br>
To explain this complex process I have started this project to create my own hypervisor in linux. It will help understanding what minimal VT-X functionality you require as well as what bits to set and what not. <br/>
I have developed it as linux kernel module and will try to keep it update with new functionalities.
<br/>
Technical explanation can be found in this blog series: https://nixhacker.com/developing-hypervisior-from-scratch-part-1/
## Usage
Step 1: `make`
<br/>
Step 2: `sudo insmod protovirt.ko`


## Modifications
`guest_code()` is the function that will run after vmlaunch (VM Non-root code). Change it according to your requirement.
Don't forget to update `GUEST_STACK_SIZE` macro for bigger stack for guest.
