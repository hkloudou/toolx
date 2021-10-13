.PHONY: default
.DEFAULT_GOAL := default
default:
	-git autotag -commit 'auto commit' -t -i -f -p
	@echo current version:`git describe`
init-ssl:
	@#openssl genrsa -out private.pem 1024
	@#openssl rsa -in private.pem -pubout -out public.pem