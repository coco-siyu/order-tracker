Resolved the 5xx incident.

- Root cause: express delivery calculation used `datetime.replace(day=day + 2)`, producing an invalid date at month end.
- Fix: use `timedelta(days=2)` in [app/main.py](/Users/cocochen/Downloads/github/zoomcamp/order-tracker/app/main.py:58).
- Added month-boundary regression coverage in [tests/test_api.py](/Users/cocochen/Downloads/github/zoomcamp/order-tracker/tests/test_api.py:40).
- Confirmed `/api/orders/express-1002` changed from `500` to `200`.
- Full suite: **7 passed**. Two unrelated dependency deprecation warnings remain.

Incident evidence and unrelated existing changes were untouched.