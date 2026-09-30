# image_builder tests

Host-only pytest suite for `image_builder.py`, `nvm_config.py` and `strip.py`; no toolchain or Phoenix-RTOS build is needed.

```sh
pip install -r requirements.txt
python3 -m pytest scripts/tests
```

Coverage, as checked by CI (`pip install coverage`):

```sh
coverage run --rcfile=scripts/tests/.coveragerc -m pytest scripts/tests
coverage report --rcfile=scripts/tests/.coveragerc
```
