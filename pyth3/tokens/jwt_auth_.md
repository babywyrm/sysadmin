## Notice

Originally did this research during my work for Bitwyre.
I'm now open-sourcing this and hope this helps anyone who finds it, please let me know by commenting if this did help you!

# JWT on Python

The `access_token` produced by Auth Server (a token grant OAuth2.0) is actually a JWT token itself, but is using a different length and algorithm than your typical JWT.

It is using `RS256` rather that the common `HS256` algo.

Try pasting the following `access_token` to [jwt.io](https://jwt.io)

```
eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp0aSI6IjdlZDhmODMzY2RlZjkzMzgxODk4ZWVlYmFkYTc3Mzg0MDhlYTU3YWRkYmM5Mzg1MDI2ZTMzYTM0OTkxMDgyOGZjNGFkZDA5MGMyYmU4MjBiIn0.eyJhdWQiOiIyIiwianRpIjoiN2VkOGY4MzNjZGVmOTMzODE4OThlZWViYWRhNzczODQwOGVhNTdhZGRiYzkzODUwMjZlMzNhMzQ5OTEwODI4ZmM0YWRkMDkwYzJiZTgyMGIiLCJpYXQiOjE1NzA3Mzk4MDUsIm5iZiI6MTU3MDczOTgwNSwiZXhwIjoxNTcwNzQwNzA1LCJzdWIiOiJjNGE3NjBhOC1kYmNmLTUyNTQtYTBkOS02YTQ0NzRiZDFiNjIiLCJzY29wZXMiOltdfQ.NDpnCkSCUMtnXhPtZX8UVTkSF-QmKqU4TH0ws3Gx-PtPL857WJTKOQHG7FS_0jPIWOiAT1rb1HwqXq1y-UZUdn8tR86Rt69QMteuER-r3tMPVBHgaUCVw6RT006gEyiVQrmD1Bb65FMXB26Vy_fDxleMlkrspGItAU0FGSd59wsl_WxdYZJF_uki9GRd3hmB86OiXjA8GflCO_gIUFhwhBdzrEzazQpgPw_LIP_r0pQF6ai8POqOFINJMfzzNW6osIaHlGHM0opoJz2q7-uHpuyfvfHQQjZQVquF0LWTHaEGxYlbLaz8wVqxoT1JWqyUrGjrUxn-a5xbBzeLjVUmJ-IRsFgsvDCv8g2QtywFqboL8RLMpGy29aOo9QPd7Ne0pqs3t4AXk8XA2Bcuo-rm7O15peByY_Grhvtw4uewTIThFGGuyjkIEs95lSABI_1fRWBJIUR2n0_x_Km95F8NJ5aIuFSMzQD-7ckfTdLUs32xh6UaVJtqSP4NwIkwDMqfiYNwhx01MMnCcgsrZIF-kO8jFCuAh9Vt1JlIwIvR7_mPEb72fcyF6vwyt46NhvXx7jXZfcFjo5x3wUopVnobbnLRHCkG5CLNtTrdyiFJAZJ57BR4mqKUIT83hLKRgGDhRLm-4Sq3ab4NxC57XMA4ha-JFaN4iJ-C7NGikSdDuJ4
```

That's why we can actually use this `access_token` as a JWT token!

Check out [PyJWT](https://pyjwt.readthedocs.io/en/latest/usage.html#encoding-decoding-tokens-with-rs256-rsa)

```bash
pip install pyjwt[crypto]
```

Pro Tip: If you're using `zsh` and it complained `zsh: no matches found: pyjwt[crypto]`

```bash
pip install pyjwt
pip install cryptography
```

To verify the authenticity of a given token, the `public_key` of the `private_key` that was used to generate the token, is needed. Auth Server is the one that handles this certificate and passing the `public_key` to any 1st party app shouldn't pose a threat.

```python
import jwt

token = b'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp0aSI6IjdlZDhmODMzY2RlZjkzMzgxODk4ZWVlYmFkYTc3Mzg0MDhlYTU3YWRkYmM5Mzg1MDI2ZTMzYTM0OTkxMDgyOGZjNGFkZDA5MGMyYmU4MjBiIn0.eyJhdWQiOiIyIiwianRpIjoiN2VkOGY4MzNjZGVmOTMzODE4OThlZWViYWRhNzczODQwOGVhNTdhZGRiYzkzODUwMjZlMzNhMzQ5OTEwODI4ZmM0YWRkMDkwYzJiZTgyMGIiLCJpYXQiOjE1NzA3Mzk4MDUsIm5iZiI6MTU3MDczOTgwNSwiZXhwIjoxNTcwNzQwNzA1LCJzdWIiOiJjNGE3NjBhOC1kYmNmLTUyNTQtYTBkOS02YTQ0NzRiZDFiNjIiLCJzY29wZXMiOltdfQ.NDpnCkSCUMtnXhPtZX8UVTkSF-QmKqU4TH0ws3Gx-PtPL857WJTKOQHG7FS_0jPIWOiAT1rb1HwqXq1y-UZUdn8tR86Rt69QMteuER-r3tMPVBHgaUCVw6RT006gEyiVQrmD1Bb65FMXB26Vy_fDxleMlkrspGItAU0FGSd59wsl_WxdYZJF_uki9GRd3hmB86OiXjA8GflCO_gIUFhwhBdzrEzazQpgPw_LIP_r0pQF6ai8POqOFINJMfzzNW6osIaHlGHM0opoJz2q7-uHpuyfvfHQQjZQVquF0LWTHaEGxYlbLaz8wVqxoT1JWqyUrGjrUxn-a5xbBzeLjVUmJ-IRsFgsvDCv8g2QtywFqboL8RLMpGy29aOo9QPd7Ne0pqs3t4AXk8XA2Bcuo-rm7O15peByY_Grhvtw4uewTIThFGGuyjkIEs95lSABI_1fRWBJIUR2n0_x_Km95F8NJ5aIuFSMzQD-7ckfTdLUs32xh6UaVJtqSP4NwIkwDMqfiYNwhx01MMnCcgsrZIF-kO8jFCuAh9Vt1JlIwIvR7_mPEb72fcyF6vwyt46NhvXx7jXZfcFjo5x3wUopVnobbnLRHCkG5CLNtTrdyiFJAZJ57BR4mqKUIT83hLKRgGDhRLm-4Sq3ab4NxC57XMA4ha-JFaN4iJ-C7NGikSdDuJ4'
public_key = b'-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxgKxfus3AanXHPhoXInznJfDGHZuHDjKqWe63YxsNwJm0Ez6csnpkDXy8eKDjTj/FB7YcAgwz9X3J4G9wTEE8PIKC3HarVONfSSKHkBWYv1YKe4aJlh5R0CFcQ5ORh37PkQmPKhwK6VpvE/OUX38KgblHkDo0tLIxgcZ/n8l7nZM18TELqscvtLQ9DkSu20GGsmo85Xiy+tLlsPKXhZLYHpqGNFNGwQ9Olva29YlZQkPXf+bOH325nnLiw5gGeN1iVUR08dEJj68ZSt8S9dGSwag+4jYlQlW849b/rOQgzNqjUINabES+8zJ7cwyJYnyNhC611VpnfDTsP0vgObICNqkxDeSPgg40SAG5vzVf4adRW4WBHB6TTPGfCK5D+43gv5dsa7pu185RvvJq+ayq7gf8rINbsddY8foMugfxd4OcXLVUpXw+ohYEMpjqxYgsMS0KKCmedwkJHAD2TwdfmXeTefkZxVVCExRlCMS721rnV+F3xp1S07pmDYscqTm9LSDcubzLnuyXrGutRVNfjWQZ+HGPa7tcPDc4zlL6J6EfNnhQHUDhAtRaM4fVnFadR5Yf48A2wdaMFSyEvo9d5yCkW9uWftFftA+3ta0WIdssvTN4qOLr0AYKpYM6siP+1GWrzIIhhZUShGuC9JkIKZE/76ce+yusv7fp2OOB4kCAwEAAQ==\n-----END PUBLIC KEY-----'

jwt.decode(token, public_key, audience='2', algorithms=['RS256'])
```

Success!
```bash
{'aud': '2', 'jti': '7ed8f833cdef93381898eeebada7738408ea57addbc9385026e33a349910828fc4add090c2be820b', 'iat': 1570739805, 'nbf': 1570739805, 'exp': 1570740705, 'sub': 'c4a760a8-dbcf-5254-a0d9-6a4474bd1b62', 'scopes': []}
```

After the token's authenticity and validity has been proven, continue processing the request as usual.

### Exceptions

Validation Failed! (from e.g wrong token)
```bash
jwt.exceptions.InvalidSignatureError: Signature verification failed
```

Expired Token!
```bash
jwt.exceptions.ExpiredSignatureError: Signature has expired
```

## Some things to pay attention to

### Line Break

A line break `\n` needs to be added after `-----BEGIN PUBLIC KEY-----` AND before `-----END PUBLIC KEY-----`!

Otherwise you'll get

```bash
ValueError: Could not deserialize key data.
```

### Audience Argument

Notice the additional argument `audience` there, value would almost always be `2` unless there are changes on the Auth Server side, and if it's not there, you'll get

```bash
jwt.exceptions.InvalidAudienceError: Invalid audience
```

#### Footnote

(I'm the original author of this document and this previously has been forked privately here https://gist.github.com/dendisuhubdy/8f548cafc584d7178cf95e90d7cd45a2)
