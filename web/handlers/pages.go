package handlers

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

func Dashboard(c echo.Context) error {
	return c.Render(http.StatusOK, "dashboard.html", nil)
}

func TablesBasic(c echo.Context) error {
	return c.Render(http.StatusOK, "tables-basic.html", nil)
}
