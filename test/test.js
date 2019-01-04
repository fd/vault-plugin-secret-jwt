const assert = require('assert');
const fetch = require('node-fetch');
const jwt = require('jsonwebtoken');

describe('Roles', function() {

  it('should accept empty spec', async () => {
    const id = randRoleName();


    const resp1 = await write(`jwt/role/${id}`, {});
    assert.equal(resp1.status, 204);
    assert.equal(resp1.body, null);

    const resp2 = await read(`jwt/role/${id}`);
    assert.equal(resp2.status, 200);
    assert.deepEqual(resp2.body.data, {
      defaults: '',
      name: 'role0',
      overrides: '',
      schema: '',
      ttl: 3600
    });

    const resp3 = await write(`jwt/sign/${id}`, {
      claims: JSON.stringify({
        scopes: ["posts.write"]
      }),
    });
    assert.equal(resp3.status, 200);
    const claims = await verifyJWT(resp3.body.data.token);
    assert.deepEqual(claims.scopes, ["posts.write"]);
  });

  it('should accept none empty spec', async () => {
    const id = randRoleName();


    const resp1 = await write(`jwt/role/${id}`, {
      defaults: JSON.stringify({
        "aud": ["https://example.com"],
      }),
      overrides: JSON.stringify({
        "iss": "https://example.net",
      }),
      schema: JSON.stringify({
        properties: {
          scopes: {
            type: "array",
            items: {
              type: "string"
            }
          }
        }
      }),
    });
    assert.equal(resp1.status, 204);
    assert.equal(resp1.body, null);

    const resp2 = await read(`jwt/role/${id}`);
    assert.equal(resp2.status, 200);
    assert.deepEqual(resp2.body.data, {
      defaults: "{\"aud\":[\"https://example.com\"]}",
      name: "role1",
      overrides: "{\"iss\":\"https://example.net\"}",
      schema: "{\"properties\":{\"scopes\":{\"type\":\"array\",\"items\":{\"type\":\"string\"}}}}",
      ttl: 3600
    });

    const resp3 = await write(`jwt/sign/${id}`, {
      claims: JSON.stringify({
        scopes: ["posts.write"]
      }),
    });
    assert.equal(resp3.status, 200);
    const claims = await verifyJWT(resp3.body.data.token);
    assert.deepEqual(claims.aud, ["https://example.com"]);
    assert.deepEqual(claims.iss, "https://example.net");
    assert.deepEqual(claims.scopes, ["posts.write"]);
  });

  it('should reject invalid defaults', async () => {
    const resp = await write(`jwt/role/${randRoleName()}`, {
      defaults: JSON.stringify({
        nbf: 1264,
        exp: 464645,
        iat: 469,
        iss: "foo",
      }),
    });

    assert.equal(resp.status, 400);
    assert.deepEqual(resp.body, {
      errors: [
        "/exp: \"exp\" cannot match schema",
        "/iat: \"iat\" cannot match schema",
        "/iss: \"iss\" cannot match schema",
        "/nbf: \"nbf\" cannot match schema",
      ]
    });
  });

  it('should reject invalid overrides', async () => {
    const resp = await write(`jwt/role/${randRoleName()}`, {
      overrides: JSON.stringify({
        nbf: 1264,
        exp: 464645,
        iat: 469,
        iss: "foo",
      }),
    });

    assert.equal(resp.status, 400);
    assert.deepEqual(resp.body, {
      errors: [
        "/exp: \"exp\" cannot match schema",
        "/iat: \"iat\" cannot match schema",
        "/nbf: \"nbf\" cannot match schema",
      ]
    });
  });

  it('should reject invalid schema', async () => {
    const resp = await write(`jwt/role/${randRoleName()}`, {
      schema: JSON.stringify({
        type: "xyz",
      }),
    });

    assert.equal(resp.status, 400);
    assert.deepEqual(resp.body, {
      errors: [
        "/type: \"xyz\" did Not match any specified AnyOf schemas",
      ]
    });
  });

});

async function write(path, body) {
  const res = await fetch(`http://localhost:8200/v1/${path}`, {
    method: "POST",
    body: JSON.stringify(body),
    headers: {
      'X-Vault-Token': 'root',
      'Content-Type': 'application/json'
    },
  });

  if (res.status == 204) {
    return {
      status: res.status,
      body: null,
    };
  }
  if (res.headers.get('content-type') != 'application/json') {
    return {
      status: res.status,
      body: null,
    };
  }

  const resbody = await res.json();
  return {
    status: res.status,
    body: resbody
  };
}

async function read(path) {
  const res = await fetch(`http://localhost:8200/v1/${path}`, {
    method: "GET",
    headers: {
      'X-Vault-Token': 'root',
      'Content-Type': 'application/json'
    },
  });

  if (res.status == 204) {
    return {
      status: res.status,
      body: null,
    };
  }
  if (res.headers.get('content-type') != 'application/json') {
    return {
      status: res.status,
      body: null,
    };
  }

  const resbody = await res.json();
  return {
    status: res.status,
    body: resbody
  };
}

async function getKey(header) {
  const res = await read(`jwt/key/${header.kid}`);
  if (res.status != 200) {
    throw new Error("unexpected status");
  }
  return res.body.data.public;
}

function verifyJWT(token) {
  return new Promise((resolve, reject) => {
    const getKeyCB = async (header, callback) => {
      try {
        callback(null, await getKey(header));
      } catch (e) {
        callback(e);
      }
    }

    jwt.verify(token, getKeyCB, {
      algorithms: ['RS256'],
    }, function(err, decoded) {
      if (err) {
        reject(err);
      } else {
        resolve(decoded);
      }
    });
  });

}

let roleCounter = 0;

function randRoleName() {
  return `role${roleCounter++}`;
}
