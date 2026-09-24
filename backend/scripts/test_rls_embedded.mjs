// Optional SQL-level regression check using PostgreSQL compiled to WASM.
// Full psycopg/PG16 integration still runs separately in CI.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
const modulePath = process.argv[2];
if (!modulePath) throw new Error('Pass the installed @electric-sql/pglite module path.');
const { PGlite } = await import(modulePath);
const db = new PGlite();
const statements = JSON.parse(execFileSync('python', ['-c', 'import json; from app.persistence.schema import SCHEMA_STATEMENTS; print(json.dumps(SCHEMA_STATEMENTS))'], { encoding:'utf8' }));
await db.exec('CREATE ROLE anon; CREATE ROLE authenticated;');
for (const sql of statements) await db.exec(sql);
// Re-running the schema must not weaken policies or fail.
for (const sql of statements) await db.exec(sql);
const alice='00000000-0000-0000-0000-000000000001', bob='00000000-0000-0000-0000-000000000002';
const insert = "INSERT INTO investigations(owner_id,input_type,content,threat_score,verdict,confidence,reasoning) VALUES ($1,'text','synthetic',0,'Inconclusive',0,'test') RETURNING id";
async function asUser(owner, fn) {
  return db.transaction(async tx => {
    await tx.exec('SET LOCAL ROLE evidence_app');
    if (owner) await tx.query("SELECT set_config('app.user_id', $1, true)", [owner]);
    return fn(tx);
  });
}
const aid=(await asUser(alice, tx=>tx.query(insert,[alice]))).rows[0].id;
const bid=(await asUser(bob, tx=>tx.query(insert,[bob]))).rows[0].id;
assert.equal((await asUser(alice, tx=>tx.query('SELECT * FROM investigations'))).rows.length,1);
assert.equal((await asUser(bob, tx=>tx.query('SELECT * FROM investigations WHERE id=$1',[aid]))).rows.length,0);
assert.equal((await asUser(null, tx=>tx.query('SELECT * FROM investigations'))).rows.length,0);
await assert.rejects(asUser(alice, tx=>tx.query(insert,[bob])));
await assert.rejects(asUser(alice, tx=>tx.query('UPDATE investigations SET owner_id=$1 WHERE id=$2',[bob,aid])));
await assert.rejects(asUser(alice, tx=>tx.query("INSERT INTO artifacts(investigation_id,filename) VALUES($1,'cross-user')",[bid])));
await asUser(alice, tx=>tx.query("INSERT INTO artifacts(investigation_id,filename) VALUES($1,'own')",[aid]));
assert.equal((await asUser(bob, tx=>tx.query('SELECT * FROM artifacts'))).rows.length,0);
assert.equal((await asUser(bob, tx=>tx.query('DELETE FROM investigations WHERE id=$1 RETURNING id',[aid]))).rows.length,0);
await assert.rejects(db.transaction(async tx=>{ await tx.exec('SET LOCAL ROLE anon'); return tx.query('SELECT * FROM investigations'); }));
await assert.rejects(db.transaction(async tx=>{ await tx.exec('SET LOCAL ROLE authenticated'); return tx.query('SELECT * FROM investigations'); }));
await assert.rejects(asUser(alice, tx=>tx.query('SELECT * FROM usage_budgets')));
await db.transaction(async tx=>{ await tx.exec('SET LOCAL ROLE evidence_budget'); await tx.exec("INSERT INTO usage_budgets VALUES ('global:test',1)"); });
await asUser(alice, tx=>tx.query('DELETE FROM investigations WHERE id=$1',[aid]));
assert.equal((await db.query('SELECT * FROM artifacts')).rows.length,0);
console.log('PASS: idempotent schema; own rows; missing identity; cross-user reads, inserts, ownership updates, deletes; child isolation/cascade; browser roles denied; budgets isolated.');
await db.close();
