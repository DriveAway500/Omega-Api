# Work in Progress

This repository is still a work in progress. Development has just started, and many features still need to be implemented.

## What to do if you're using this

If, by some miracle, you decided to use this code, here's what you need to know.

### Setting up the repositories

Before setting up the API, you need to clone both the `0.daytoday.archive` and `exploitdb` repositories.

### Updating the databases

To update your local data, run the following scripts:

- `update_gitbased.sh`
- `update_nvd_db.sh`

**Be careful with `update_nvd_db.sh`.** The NVD API enforces rate limits, and excessive requests may result in your requests being temporarily restricted. The code already includes safeguards to help prevent this, but don't abuse the API anyway.

### API routes

All API routes are currently defined in `main`.

**Do not expose this API directly to the internet yet.** The endpoints are not production-ready, and additional work is needed before the API can be safely deployed publicly.

I'll add more documentation about the routes and their usage as development progresses.

## Things you need to know

### `DATA/`

The `DATA/` directory stores links to the NVD API resources and the timestamp of the last fetch.

If you find outdated links, try pulling the latest changes from this repository first.

If the links haven't been updated here yet, you can update them manually using the NVD website. If you do, please commit your changes so everyone can benefit from them :D.

### `Scripts/`

This directory is probably temporary. I plan to integrate the update scripts into the main codebase eventually.

## Want to help?

Contributions are welcome! Feel free to commit your changes to the repository.

One thing, though: **please don't run AI tools over `src/utils/` or any other code explicitly tagged as human-written.** Those sections are meant to preserve human-written code and its original design.

Contributions that ignore this rule will be rejected.

More contribution guidelines may be added as the project evolves.