
# Schedule the task of obtaining updates for worldwide contacts
from covidtrackapi.models import  WorldUpdate
from covidtrackapi import db
import requests, json
from datetime import  datetime
def fetchWorldUpdates():
    continent_data = requests.get(url='https://corona.lmao.ninja/v2/continents?yesterday=false&sort=')
    country_data = requests.get(url='https://corona.lmao.ninja/v2/countries?yesterday=false&sort=')

    continent_data_json = continent_data.json()
    country_data_json = country_data.json()


    country_db_data =  {}
    continent_db_data = {}
    data = []
    updatedate = datetime.utcnow()

    # Get the database Content
    db_content = WorldUpdate.query.all()
    if len(db_content) == 0:
        update_country = WorldUpdate(context='country', data=json.dumps(country_data_json), lastupdate=updatedate)
        update_continent = WorldUpdate(context='continent', data=json.dumps(continent_data_json), lastupdate=updatedate)
        db.session.add_all((update_country, update_continent))
        try:
            db.session.commit()
        except Exception as e:
            print(e)
    else:
        data = [{'context': db_data.context, 'data':json.loads(db_data.data), 'lastupdate':db_data.lastupdate} for db_data in db_content]

        # print(f'JSON DATA: {country_data_json}')
        # print(f'DB DATA: {country_db_data}')

        for d in data:
            if d['context'] == 'country':
                country_db_data = d['data']
                for idx in range(len(country_db_data)):
                    for key in country_db_data[idx].keys():
                        if country_db_data[idx][key] != country_data_json[idx][key]:
                            country_db_data[idx][key] = country_data_json[idx][key]
            else:
                continent_db_data = d['data']
                for idx in range(len(continent_db_data)):
                    for key in continent_db_data[idx].keys():
                        if continent_db_data[idx][key] != continent_data_json[idx][key]:
                            continent_db_data[idx][key] = continent_data_json[idx][key]
        for data in db_content:
            if data.context=='country':
                data.data = json.dumps(country_db_data)
                data.lastupdate = updatedate
            else:
                data.data = json.dumps(continent_db_data)
                data.lastupdate = updatedate

        try:
            db.session.commit()
        except Exception as e:
            print(e)