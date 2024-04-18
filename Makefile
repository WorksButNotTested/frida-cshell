PREFIX:=frida-cshell
STEPS:=	$(shell grep "^FROM" Dockerfile | cut -d " " -f 4)

.PHONY: all

all: $(STEPS)

define BUILD_STEP
$(1):
	DOCKER_BUILDKIT=1 \
	docker build \
		--build-arg http_proxy=$$$$http_proxy \
		--build-arg https_proxy=$$$$https_proxy \
		-t $(PREFIX)-$(1) \
		--target $(1) \
		.

run-$(1): $(1)
	docker run \
		-ti \
		--rm \
		--name $(PREFIX)-$(1) \
		-u root \
		-v $(HOME):/home/share \
		$(PREFIX)-$(1)
endef

$(foreach step,$(STEPS),$(eval $(call BUILD_STEP,$(step))))


save: $(STEPS)
	docker save $(foreach step,$(STEPS),$(PREFIX)-$(step)) | xz -T0 -c > $(PREFIX)-images.tar.xz

prune:
	docker builder prune -f
	docker image prune -f
