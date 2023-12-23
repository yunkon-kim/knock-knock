default:
	cd cmd/knock-knock && $(MAKE)

cc:
	cd cmd/knock-knock && $(MAKE)

run:
	cd cmd/knock-knock && $(MAKE) run

runwithport:
	cd cmd/knock-knock && $(MAKE) runwithport --port=$(PORT)

clean:
	cd cmd/knock-knock && $(MAKE) clean

prod:
	cd cmd/knock-knock && $(MAKE) prod

swag swagger:
	cd pkg/ && $(MAKE) swag
