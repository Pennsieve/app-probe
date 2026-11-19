.PHONY: test image run-local clean

IMAGE ?= app-probe:local

test:
	python3 -m unittest discover -s tests -v

image:
	docker build -t $(IMAGE) .

# Run the image the way a compute node does: uid 1000, read-only inputs,
# INPUT_DIR and OUTPUT_DIR under /data. The report lands in ./out.
run-local: image
	mkdir -p out && chmod 777 out
	docker run --rm --user 1000:1000 \
		-v $(CURDIR)/tests/fixtures:/data/input:ro \
		-v $(CURDIR)/out:/data/output \
		-e INPUT_DIR=/data/input -e OUTPUT_DIR=/data/output \
		-e EXECUTION_RUN_ID=local-run -e ENVIRONMENT=local \
		$(IMAGE)

clean:
	rm -rf out
