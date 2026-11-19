PY := python3

.PHONY: test fixtures analyze clean

test:
	$(PY) tools/test_tools.py -v

fixtures:
	$(PY) tools/pcapgen.py --out fixtures

analyze:
	$(PY) tools/pcap_analyze.py $(FILE) $(MODE)

clean:
	rm -rf fixtures tools/__pycache__
