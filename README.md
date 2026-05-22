# st-gws-pi

Enhanced Google Workspace extension for [pi](https://github.com/earendil-works/pi) coding agent.

Fork of [pi-google-workspace](https://github.com/Geun-Oh/pi-google-workspace) with additional tools.

## Installation

```bash
pi install npm:@steimbyte/st-gws-pi
```

## Additional Tools

This fork adds these tools on top of the original:

| Tool | Description |
|------|-------------|
| `google_docs_insert_text` | Insert text at a specific index position |
| `google_docs_find_and_replace` | Find and replace text without index calculation |

## Original Tools

- `google_workspace_status` - Check OAuth status
- `google_drive_list` - List Drive files
- `google_drive_download` - Download files
- `google_drive_upload` - Upload files
- `google_drive_create_folder` - Create folders
- `google_sheets_create` - Create spreadsheets
- `google_sheets_read` - Read sheet data
- `google_sheets_update_values` - Update sheet values
- `google_docs_read` - Read document
- `google_docs_create` - Create document
- `google_docs_replace_all_text` - Replace entire body
- `google_docs_append_text` - Append text to end
- `google_docs_download` - Export document
- `google_slides_read` - Read presentation
- `google_slides_replace_text` - Replace in slides

## Setup

```bash
/gws-setup
```

## License

MIT
