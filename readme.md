# ODRL-Gateway

ODRL-Gateway is a modular policy enforcement layer designed to integrate with Solid-based applications and servers. It enables automatic injection and replacement of gateway logic, templates, and ODRL-based policy controls into an existing Solid project.

---

## Features

* ODRL-based policy evaluation
* Automatic integration into Solid projects
* Folder injection & override (templates, odrl, gateway)
* Plug-and-play via npm installation

---

## Compatibility

ODRL-Gateway has been tested with the following environment:

### Solid Ecosystem

* Community Solid Server: **v7.x – v8.x**
* Other Solid servers may work but are not officially tested

### Runtime & Language

* Node.js: **>= 18.x** (recommended: 18 / 20 LTS)
* ECMAScript Modules (ESM): **required** (`"type": "module"`)

### Package Manager

* npm: **>= 8.x**
* yarn / pnpm: not fully tested

---

## Installation

Install directly into your Solid project:

```bash
npm install ahmadvoc12/ODRL-Gateway
```

---

## How It Works

After installation, a `postinstall` script runs automatically.

This script will:

* Inject ODRL gateway logic into your project
* Replace selected folders/files with ODRL-Gateway versions
* Create backups of replaced files

---

## Affected Files

The following will be injected or replaced in your Solid project:

* `templates/`
* `odrl/`
* `gateway.mjs`

If these already exist, they will be:

* Backed up → `*.backup`
* Replaced with ODRL-Gateway versions

---

## Example

Before installation:

```bash
solid-project/
├── templates/
├── server.js
```

After installation:

```bash
solid-project/
├── templates/         ← replaced
├── templates.backup/  ← original backup
├── odrl/              ← added
├── gateway.mjs        ← added
```

---

## Manual Re-run

To re-run the injection manually:

```bash
node node_modules/odrl-gateway/postinstall.js
```

---

## Important Notes

* This package modifies your project structure automatically
* Always commit or backup your project before installation
* Not all Solid project structures are identical — adjust if needed
* This approach is suitable for research, prototyping, and controlled environments

---

## Development Mode

Use local development version:

```bash
# inside ODRL-Gateway repo
npm link

# inside Solid project
npm link odrl-gateway
```

---

## Architecture Insight

ODRL-Gateway acts as a policy enforcement layer on top of the Solid ecosystem. Instead of modifying the Solid core, it injects:

* Access control logic
* Policy evaluation mechanisms
* Template-level enforcement hooks

This enables modular experimentation with ODRL, DPV, and semantic policy frameworks.

---

## Acknowledgment & Citation

This work builds upon the Solid ecosystem and its server implementations, particularly the Community Solid Server.

If the Community Solid Server played a role in your scientific publication, please cite:

```bibtex
@article{CommunitySolidServer,
  title   = {The Community Solid Server: Supporting research \& development in an evolving ecosystem},
  author  = {Van Herwegen, Joachim and Verborgh, Ruben},
  journal = {Semantic Web},
  volume  = {15},
  number  = {6},
  pages   = {2597--2611},
  year    = {2024},
  doi     = {10.3233/SW-243726},
  url     = {https://journals.sagepub.com/doi/abs/10.3233/SW-243726}
}
```

---

## Contributing

Contributions, issues, and suggestions are welcome.

---

## License

MIT License
