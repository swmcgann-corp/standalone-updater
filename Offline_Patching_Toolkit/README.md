# Standalone Updater

For Windows 11 x64 with Defender, Edge Stable, and Office LTSC Professional Plus 2021 or 2024 (English `en-us`, 32-bit or 64-bit, Click-to-Run).

## 1. Prepare the package - connected PC

Open **64-bit Windows PowerShell** in the toolkit folder and run:

```powershell
.\Prepare-OfflinePackage.ps1 -OutputDirectory 'C:\OfflineDeployments'
```

Allow **25 GB free** on the output drive. Downloads include the scan catalog, Defender updates, Edge, and separate 32-bit and 64-bit sources for both Office releases. Wait for **READY**. Never use a folder ending in `.incomplete`. Prepare a new package to add 2024 support; don't modify an existing ready folder.

## 2. Transfer the folder - standalone PC

Copy the **entire ready folder** onto the standalone PC using approved transfer media. Do not change its contents.

Confirm a backup is available, save your work, and close Office and Edge. Double-click [Start-OfflineUpdate.cmd](Start-OfflineUpdate.cmd) and approve the administrator prompt.

## 3. Update and review

Choose **1 - Update and Report**, then type **UPDATE** to confirm.

The tool updates Defender, Edge, and Office, scans for missing Windows patches, and opens **OfflineUpdateReport.html** with the patch list and software versions. The same package works on both Office releases: it selects the installed edition, update channel, and bitness without migrating Office or changing its licensing.

If a restart is requested, restart manually and choose **Update and Report** again to finish. If an update fails, resolve the reported error before continuing.

Reports are saved locally for each PC and run:

```text
%ProgramData%\StandaloneUpdater\Reports\<ComputerName>\<date_time_id>\
```

## 4. Install Windows patches manually

Record the report's **KB numbers, Windows release, and architecture**. On the connected PC, download matching patches from [Microsoft Update Catalog](https://www.catalog.update.microsoft.com/).

Transfer the patches in a **separate folder**, install them manually, and restart as required. Follow Microsoft's prerequisite/checkpoint instructions; the report is **not** an installation-order list.

## 5. Verify

Run the launcher again and choose **2 - Verify Only**. This refreshes the patch list and software inventory without reinstalling products.

Repeat manual patching and verification until no catalog-covered patches, update failures, or pending restarts remain. Reports never need to leave the standalone PC.

## Important

- Defender **platform** updates (KB4052623) remain manual; intelligence/engine updates are automatic.
- Office 2021 support ended **October 13, 2026**. Arrange its upgrade separately with IT.
- A clean scan covers only the packaged catalog, not every possible patch. Prepare a fresh package for each patching cycle or when the catalog is flagged as old.
- If downloads, signatures, or script policies block progress, stop and ask IT. Do not bypass the checks.

