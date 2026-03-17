// Copyright (c) 2025, Frappe Technologies and contributors
// For license information, please see license.txt

frappe.query_reports["User Access Management"] = {
	filters: [
		{
			fieldname: "from_date",
			label: __("From Date"),
			fieldtype: "Date",
			reqd: 1,
			default: frappe.datetime.add_months(frappe.datetime.get_today(), -3),
		},
		{
			fieldname: "to_date",
			label: __("To Date"),
			fieldtype: "Date",
			reqd: 1,
			default: frappe.datetime.get_today(),
		},
		{
			fieldname: "type",
			label: __("Type"),
			fieldtype: "Select",
			reqd: 1,
			options: [
				"Users Granted Access",
				"Users Access Modified",
				"Users Access Revoked",
				"Active Users With Roles",
				"Privileged Users",
				"Password Reset Status",
			].join("\n"),
			default: "Active Users With Roles",
			on_change: function () {
				const is_privileged =
					frappe.query_report.get_filter_value("type") === "Privileged Users";
				frappe.query_report.toggle_filter_display("privileged_roles", !is_privileged);
				if (!is_privileged) {
					frappe.query_report.set_filter_value("privileged_roles", "");
				}
			},
		},
		{
			fieldname: "company",
			label: __("Company"),
			fieldtype: "Link",
			options: "Company",
		},
		{
			fieldname: "privileged_roles",
			label: __("Privileged Roles"),
			fieldtype: "MultiSelectList",
			get_data: function (txt) {
				return frappe.db.get_link_options("Role", txt);
			},
		},
	],

	onload: function () {
		// Ensure the privileged_roles filter starts hidden
		frappe.query_report.toggle_filter_display("privileged_roles", true);
	},
};
