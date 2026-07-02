#!/usr/bin/env node
// Wrapper - forwards to the installed CSS server
import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import path from 'path';
import { AppRunner } from '@solid/community-server';

const runner = new AppRunner();
runner.run({ loggingLevel: 'error' });
