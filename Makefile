PY := python3

MD ?= docs/deep-dive.md
OUT ?= $(basename $(MD)).pdf

.PHONY: test fixtures analyze diagram pdf clean

test:
	$(PY) tools/test_tools.py -v

pdf:
	$(PY) tools/md2pdf.py $(MD) -o $(OUT)

fixtures:
	$(PY) tools/pcapgen.py --out fixtures

diagram:
	$(PY) tools/diagram.py

analyze:
	$(PY) tools/pcap_analyze.py $(FILE) $(MODE)

clean:
	rm -rf fixtures tools/__pycache__
