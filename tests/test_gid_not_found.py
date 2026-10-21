import pytest

import torrent


@pytest.mark.parametrize(
    ('message', 'expected'),
    [
        ("{'code': 1, 'message': 'GID 717fd066996c1e0c is not found'}", True),
        ("{'code': 1, 'message': 'GID 0123456789ABCDEF is not found'}", True),
        ('RPC transport error: timeout', False),
        (
            "RPC non-JSON response: '<h1>The requested URL is not found</h1>'",
            False,
        ),
        ("{'code': 1, 'message': 'Unauthorized'}", False),
        ('', False),
    ],
)
def test_is_gid_not_found(message, expected):
    assert torrent.is_gid_not_found(torrent.Aria2Error(message)) is expected
