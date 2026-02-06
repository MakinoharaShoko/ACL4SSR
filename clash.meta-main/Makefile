.PHONY: package update mrs

# make mrs     - Only update reject rules (mrs)
# make update  - Update mrs + show traffic (alias)
# make package - Update mrs + generate Clash Mi iOS backup

mrs:
	@./generate-reject-mrs.py

update: mrs

package: mrs
	@./generate-clashmi-backup.py
