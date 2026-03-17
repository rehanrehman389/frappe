# Copyright (c) 2024, Frappe Technologies and contributors
# For license information, please see license.txt

import frappe
from frappe import _

SYSTEM_USERS = ["Administrator", "Guest"]


def execute(filters=None):
	frappe.only_for("System Manager")
	filters = frappe._dict(filters or {})
	validate_filters(filters)
	columns = get_columns(filters)
	data = get_data(filters)
	return columns, data


def validate_filters(filters):
	if not filters.type:
		frappe.throw(_("Please select a Type"))

	if filters.type == "Privileged Users" and not filters.privileged_roles:
		frappe.throw(_("Please select at least one Privileged Role"))

	if filters.from_date > filters.to_date:
		frappe.throw(_("From Date cannot be greater than To Date"))


def get_columns(filters):
	"""Return columns based on the selected audit type."""
	base = [
		{"label": _("Full Name"), "fieldname": "full_name", "fieldtype": "Data", "width": 180},
		{"label": _("User ID"), "fieldname": "user_id", "fieldtype": "Link", "options": "User", "width": 200},
		{"label": _("Email"), "fieldname": "email", "fieldtype": "Data", "width": 200},
		{"label": _("Roles"), "fieldname": "roles", "fieldtype": "Data", "width": 250},
		{"label": _("Status"), "fieldname": "status", "fieldtype": "Data", "width": 80},
	]

	type = filters.type

	if type == "Users Granted Access":
		return base + [{"label": _("Created On"), "fieldname": "created_on", "fieldtype": "Datetime", "width": 160}]

	if type == "Users Access Modified":
		return base + [{"label": _("Last Role Modified"), "fieldname": "last_role_modified", "fieldtype": "Datetime", "width": 160}]

	if type == "Users Access Revoked":
		return base + [{"label": _("Revoked On"), "fieldname": "revoked_on", "fieldtype": "Datetime", "width": 160}]

	if type == "Active Users With Roles":
		return base + [
			{"label": _("Last Login"), "fieldname": "last_login", "fieldtype": "Datetime", "width": 160},
			{"label": _("Created On"), "fieldname": "created_on", "fieldtype": "Datetime", "width": 160},
		]

	if type == "Privileged Users":
		return [
			{"label": _("Full Name"), "fieldname": "full_name", "fieldtype": "Data", "width": 180},
			{"label": _("User ID"), "fieldname": "user_id", "fieldtype": "Link", "options": "User", "width": 200},
			{"label": _("Email"), "fieldname": "email", "fieldtype": "Data", "width": 200},
			{"label": _("Privileged Roles"), "fieldname": "privileged_roles", "fieldtype": "Data", "width": 250},
			{"label": _("All Roles"), "fieldname": "roles", "fieldtype": "Data", "width": 250},
			{"label": _("Status"), "fieldname": "status", "fieldtype": "Data", "width": 80},
		]

	if type == "Password Reset Status":
		return base + [
			{"label": _("Last Password Reset Date"), "fieldname": "last_password_reset_date", "fieldtype": "Date", "width": 180},
			{"label": _("Default Password Changed"), "fieldname": "default_password_changed", "fieldtype": "Data", "width": 180},
		]

	return base


def get_data(filters):
	"""Return report data based on the selected audit type."""
	company_users = get_company_users(filters.company) if filters.company else None

	type = filters.type

	if type == "Users Granted Access":
		return get_users_granted_access(filters, company_users)

	if type == "Users Access Modified":
		return get_users_access_modified(filters, company_users)

	if type == "Users Access Revoked":
		return get_users_access_revoked(filters, company_users)

	if type == "Active Users With Roles":
		return get_active_users_with_roles(filters, company_users)

	if type == "Privileged Users":
		return get_privileged_users(filters, company_users)

	if type == "Password Reset Status":
		return get_password_reset_status(filters, company_users)

	return []


def get_company_users(company):
	"""Return users who have a User Permission for the given Company."""
	return frappe.get_all(
		"User Permission",
		filters={"allow": "Company", "for_value": company},
		pluck="user",
		distinct=True,
	)


def get_base_filters(company_users, enabled=None):
	"""Return base User filters, optionally scoped to company users and enabled state."""
	filters = {"name": ["not in", SYSTEM_USERS]}
	if enabled is not None:
		filters["enabled"] = enabled
	if company_users is not None:
		filters["name"] = ["in", company_users]
	return filters


def get_roles_map(users):
	"""Return a dict of {user: [role, ...]} for the given list of users."""
	if not users:
		return {}

	rows = frappe.get_all(
		"Has Role",
		filters={"parenttype": "User", "parent": ["in", users]},
		fields=["parent", "role"],
	)

	roles_map = {}
	for row in rows:
		roles_map.setdefault(row.parent, []).append(row.role)

	return roles_map


def build_user_row(user):
	"""Return a base row dict for a User record."""
	return {
		"full_name": user.full_name,
		"user_id": user.name,
		"email": user.email,
		"status": _("Active") if user.enabled else _("Inactive"),
	}


def attach_roles(rows, roles_map):
	"""Attach roles string to each row."""
	for row in rows:
		row["roles"] = ", ".join(sorted(roles_map.get(row["user_id"], [])))
	return rows


def get_users_granted_access(filters, company_users):
	"""Return users whose accounts were created within the audit period."""
	user_filters = get_base_filters(company_users)
	user_filters["creation"] = ["between", [filters.from_date, filters.to_date]]

	users = frappe.get_all(
		"User",
		filters=user_filters,
		fields=["name", "full_name", "email", "enabled", "creation"],
	)

	roles_map = get_roles_map([u.name for u in users])
	rows = [{**build_user_row(u), "created_on": u.creation} for u in users]
	return attach_roles(rows, roles_map)


def get_users_access_modified(filters, company_users):
	"""Return users whose role assignments were modified within the audit period."""
	has_role_filters = {
		"parenttype": "User",
		"modified": ["between", [filters.from_date, filters.to_date]],
	}

	modified_users = frappe.get_all(
		"Has Role",
		filters=has_role_filters,
		pluck="parent",
		distinct=True,
	)

	if company_users is not None:
		modified_users = [u for u in modified_users if u in company_users]

	if not modified_users:
		return []

	users = frappe.get_all(
		"User",
		filters={"name": ["in", modified_users]},
		fields=["name", "full_name", "email", "enabled"],
	)

	mod_dates = {
		r.parent: r.modified
		for r in frappe.get_all(
			"Has Role",
			filters={**has_role_filters, "parent": ["in", modified_users]},
			fields=["parent", "modified"],
			order_by="modified desc",
		)
	}

	roles_map = get_roles_map([u.name for u in users])
	rows = [{**build_user_row(u), "last_role_modified": mod_dates.get(u.name)} for u in users]
	return attach_roles(rows, roles_map)


def get_users_access_revoked(filters, company_users):
	"""Return users who were disabled within the audit period."""
	user_filters = get_base_filters(company_users, enabled=0)
	user_filters["modified"] = ["between", [filters.from_date, filters.to_date]]

	users = frappe.get_all(
		"User",
		filters=user_filters,
		fields=["name", "full_name", "email", "enabled", "modified"],
	)

	roles_map = get_roles_map([u.name for u in users])
	rows = [{**build_user_row(u), "revoked_on": u.modified} for u in users]
	return attach_roles(rows, roles_map)


def get_active_users_with_roles(filters, company_users):
	"""Return all currently active users with their roles and last login."""
	user_filters = get_base_filters(company_users, enabled=1)
	user_filters["creation"] = ["between", [filters.from_date, filters.to_date]]

	users = frappe.get_all(
		"User",
		filters=user_filters,
		fields=["name", "full_name", "email", "enabled", "last_login", "creation"],
	)

	roles_map = get_roles_map([u.name for u in users])
	rows = [{**build_user_row(u), "last_login": u.last_login, "created_on": u.creation} for u in users]
	return attach_roles(rows, roles_map)


def get_privileged_users(filters, company_users):
	"""Return users who hold any of the selected privileged roles."""
	privileged_roles = filters.privileged_roles

	priv_role_rows = frappe.get_all(
		"Has Role",
		filters={"parenttype": "User", "role": ["in", privileged_roles]},
		fields=["parent", "role"],
	)

	user_priv_roles = {}
	for row in priv_role_rows:
		user_priv_roles.setdefault(row.parent, []).append(row.role)

	user_ids = list(user_priv_roles.keys())
	if company_users is not None:
		user_ids = [u for u in user_ids if u in company_users]

	if not user_ids:
		return []

	user_filters = {"name": ["in", user_ids], "creation": ["between", [filters.from_date, filters.to_date]]}
	users = frappe.get_all(
		"User",
		filters=user_filters,
		fields=["name", "full_name", "email", "enabled"],
	)

	all_roles_map = get_roles_map([u.name for u in users])

	return [
		{
			**build_user_row(u),
			"privileged_roles": ", ".join(sorted(user_priv_roles.get(u.name, []))),
			"roles": ", ".join(sorted(all_roles_map.get(u.name, []))),
		}
		for u in users
	]


def get_password_reset_status(filters, company_users):
	"""Return active users with their password reset status."""
	user_filters = get_base_filters(company_users, enabled=1)
	user_filters["creation"] = ["between", [filters.from_date, filters.to_date]]

	users = frappe.get_all(
		"User",
		filters=user_filters,
		fields=["name", "full_name", "email", "enabled", "last_password_reset_date"],
	)

	roles_map = get_roles_map([u.name for u in users])
	rows = [
		{
			**build_user_row(u),
			"last_password_reset_date": u.last_password_reset_date,
			"default_password_changed": _("Yes") if u.last_password_reset_date else _("No"),
		}
		for u in users
	]
	return attach_roles(rows, roles_map)
