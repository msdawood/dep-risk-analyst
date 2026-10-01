import pytest

import dep_risk


@pytest.mark.smoke
def test_smoke() -> None:
    assert dep_risk.__version__ == "0.1.0"
