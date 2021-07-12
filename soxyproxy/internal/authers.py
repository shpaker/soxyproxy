from typing import Callable, Optional, Sequence


def check_authers(
    username: str,
    password: str,
    authers: Sequence[Callable[[str, str], Optional[bool]]],
) -> bool:
    for auther in authers:
        if auther(username, password) is True:
            return True
    return False
