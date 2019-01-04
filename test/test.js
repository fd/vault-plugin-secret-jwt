const assert = require('assert');
const fetch = require('node-fetch');

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

let roleCounter = 0;

function randRoleName() {
  return `role${roleCounter++}`;
}
