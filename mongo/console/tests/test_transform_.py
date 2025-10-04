import pytest
from script_name import transform_mongo_shell_to_extended_json, load_user_activity


@pytest.mark.parametrize("snippet,expected", [
    ("ISODate('2025-10-03T12:34:56Z')", '{"$date":"2025-10-03T12:34:56Z"}'),
    ("NumberLong('12345')", '{"$numberLong":"12345"}'),
    ("ObjectId('abc123')", '{"$oid":"abc123"}'),
    ("{foo: 'bar'}", '{"foo": "bar"}'),
])
def test_transforms(snippet, expected):
    output = transform_mongo_shell_to_extended_json(snippet)
    assert expected in output


def test_load_user_activity(tmp_path):
    sample = "{createdAt: '2025-10-03', resourceName: 'foo', tesupportUser: 'bob', heroUser: {email: 'x@y.com'}}"
    file_path = tmp_path / "user_activity.txt"
    file_path.write_text(sample)

    data = load_user_activity(str(file_path))
    assert isinstance(data, list)
    assert data[0]["tesupportUser"] == "bob"
