# What is this?

A very simple tool that allows DevOps to generate a link for their users to follow to register their device with TOTP as used by glauth (the simple LDAP server)

# Why Rust?

I thought about creating this project after writing [glauth_qr_Code](https://github.com/Fusion/glauth-qr-code), which was my **first** Go program.

I was able to write that program in less than a day, with some bells and whistles. It was not super-satisfying from a language nerd's standpoint, but it was unparalleled productivity.



Armed with only a superficial understanding of Rust, I created this project to compare both productivity and correctness as well as get a better grasp of the borrow checker's subtleties.

The resulting amount of time spent on the Rust version was, to say the least, expected! I am familiar with both low-level languages such as C, and functional programming. Mixing both concepts was, I found, quite challenging.

So, verdict? Well, I am enjoying Rust. But I also enjoy difficult video games so this could be all about taking down a challenging boss.

# Remaining

To achieve parity:

- The configuration file should be under GIT control
- Better error handling
- Better logging
