import random

import pytest

from santa_bot.draw import make_pairs


@pytest.mark.parametrize("n", [2, 3, 5, 8, 50])
def test_every_participant_gives_and_receives_once(n):
    people = list(range(n))
    for _ in range(200):
        pairs = make_pairs(people)
        givers = [g for g, _ in pairs]
        receivers = [r for _, r in pairs]
        assert sorted(givers) == people
        assert sorted(receivers) == people
        assert all(g != r for g, r in pairs)


@pytest.mark.parametrize("n", [2, 3, 5])
def test_pairs_form_single_cycle(n):
    pairs = dict(make_pairs(list(range(n))))
    seen, cur = set(), 0
    while cur not in seen:
        seen.add(cur)
        cur = pairs[cur]
    assert len(seen) == n


def test_example_from_spec():
    class NoShuffle(random.Random):
        def shuffle(self, x):
            pass

    assert make_pairs(["Алина", "Тимур", "Малика"], rng=NoShuffle()) == [
        ("Алина", "Тимур"),
        ("Тимур", "Малика"),
        ("Малика", "Алина"),
    ]


@pytest.mark.parametrize("items", [[], [1], [1, 1]])
def test_invalid_input(items):
    with pytest.raises(ValueError):
        make_pairs(items)
