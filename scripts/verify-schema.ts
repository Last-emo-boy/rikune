/**
 * Script to verify database schema creation
 * This script creates a test database and verifies the schema
 */

import { createDatabase } from '../src/database';
import fs from 'fs';
import path from 'path';
import os from 'os';

async function verifySchema() {
  console.log('Starting database schema verification...\n');

  // Create a temporary database
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'db-verify-'));
  const dbPath = path.join(tmpDir, 'test.db');

  try {
    // Create database
    console.log('Creating database at:', dbPath);
    const dbManager = createDatabase(dbPath);
    const db = dbManager.getDatabase();

    // Verify tables exist
    console.log('\n✓ Database created successfully');
    console.log('\nVerifying tables...');

    const tables = db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
      .all() as Array<{ name: string }>;

    const expectedTables = ['analyses', 'artifacts', 'functions', 'samples'];
    const actualTables = tables.map((t) => t.name);

    console.log('Expected tables:', expectedTables);
    console.log('Actual tables:', actualTables);

    for (const table of expectedTables) {
      if (actualTables.includes(table)) {
        console.log(`✓ Table '${table}' exists`);
      } else {
        console.error(`✗ Table '${table}' missing`);
        process.exit(1);
      }
    }

    // Verify indexes
    console.log('\nVerifying indexes...');
    const indexes = db
      .prepare("SELECT name, tbl_name FROM sqlite_master WHERE type='index' ORDER BY name")
      .all() as Array<{ name: string; tbl_name: string }>;

    const expectedIndexes = [
      'idx_analyses_sample_stage',
      'idx_analyses_status',
      'idx_artifacts_sample_type',
      'idx_functions_name',
      'idx_functions_score',
      'idx_samples_created_at',
      'idx_samples_sha256',
    ];

    const actualIndexes = indexes.map((i) => i.name).filter((name) => name.startsWith('idx_'));

    console.log('Expected indexes:', expectedIndexes);
    console.log('Actual indexes:', actualIndexes);

    for (const index of expectedIndexes) {
      if (actualIndexes.includes(index)) {
        console.log(`✓ Index '${index}' exists`);
      } else {
        console.error(`✗ Index '${index}' missing`);
        process.exit(1);
      }
    }

    // Verify foreign keys are enabled
    console.log('\nVerifying foreign keys...');
    const fkResult = db.pragma('foreign_keys') as Array<{ foreign_keys: number }>;
    if (fkResult[0].foreign_keys === 1) {
      console.log('✓ Foreign keys are enabled');
    } else {
      console.error('✗ Foreign keys are not enabled');
      process.exit(1);
    }

    // Verify table schemas
    console.log('\nVerifying table schemas...');

    // Samples table
    const samplesSchema = db.pragma('table_info(samples)') as Array<{ name: string }>;
    const samplesColumns = samplesSchema.map((c) => c.name);
    const expectedSamplesColumns = ['id', 'sha256', 'md5', 'size', 'file_type', 'created_at', 'source'];
    if (JSON.stringify(samplesColumns) === JSON.stringify(expectedSamplesColumns)) {
      console.log('✓ Samples table schema is correct');
    } else {
      console.error('✗ Samples table schema is incorrect');
      console.error('Expected:', expectedSamplesColumns);
      console.error('Actual:', samplesColumns);
      process.exit(1);
    }

    // Analyses table
    const analysesSchema = db.pragma('table_info(analyses)') as Array<{ name: string }>;
    const analysesColumns = analysesSchema.map((c) => c.name);
    const expectedAnalysesColumns = [
      'id',
      'sample_id',
      'stage',
      'backend',
      'status',
      'started_at',
      'finished_at',
      'output_json',
      'metrics_json',
    ];
    if (JSON.stringify(analysesColumns) === JSON.stringify(expectedAnalysesColumns)) {
      console.log('✓ Analyses table schema is correct');
    } else {
      console.error('✗ Analyses table schema is incorrect');
      console.error('Expected:', expectedAnalysesColumns);
      console.error('Actual:', analysesColumns);
      process.exit(1);
    }

    // Functions table
    const functionsSchema = db.pragma('table_info(functions)') as Array<{ name: string }>;
    const functionsColumns = functionsSchema.map((c) => c.name);
    const expectedFunctionsColumns = ['sample_id', 'address', 'name', 'size', 'score', 'tags', 'summary'];
    if (JSON.stringify(functionsColumns) === JSON.stringify(expectedFunctionsColumns)) {
      console.log('✓ Functions table schema is correct');
    } else {
      console.error('✗ Functions table schema is incorrect');
      console.error('Expected:', expectedFunctionsColumns);
      console.error('Actual:', functionsColumns);
      process.exit(1);
    }

    // Artifacts table
    const artifactsSchema = db.pragma('table_info(artifacts)') as Array<{ name: string }>;
    const artifactsColumns = artifactsSchema.map((c) => c.name);
    const expectedArtifactsColumns = ['id', 'sample_id', 'type', 'path', 'sha256', 'mime', 'created_at'];
    if (JSON.stringify(artifactsColumns) === JSON.stringify(expectedArtifactsColumns)) {
      console.log('✓ Artifacts table schema is correct');
    } else {
      console.error('✗ Artifacts table schema is incorrect');
      console.error('Expected:', expectedArtifactsColumns);
      console.error('Actual:', artifactsColumns);
      process.exit(1);
    }

    console.log('\n✅ All schema verifications passed!');

    // Clean up
    dbManager.close();
    fs.unlinkSync(dbPath);
    fs.rmdirSync(tmpDir);

    console.log('\n✓ Cleanup completed');
  } catch (error) {
    console.error('\n❌ Schema verification failed:', error);
    // Clean up on error
    if (fs.existsSync(dbPath)) {
      fs.unlinkSync(dbPath);
    }
    if (fs.existsSync(tmpDir)) {
      fs.rmdirSync(tmpDir);
    }
    process.exit(1);
  }
}

verifySchema();
