SUBDIRS = proxy setup

all:
	@for subdir in $(SUBDIRS); do \
		cd $$subdir            && \
		$(MAKE) all            && \
		cd ..                   ; \
	done

.PHONY: install
install:
	@for subdir in $(SUBDIRS); do \
		cd $$subdir            && \
		$(MAKE) install        && \
		cd ..                   ; \
	done

.PHONY: clean
clean:
	@for subdir in $(SUBDIRS); do \
		cd $$subdir            && \
		$(MAKE) clean          && \
		cd ..                   ; \
	done
