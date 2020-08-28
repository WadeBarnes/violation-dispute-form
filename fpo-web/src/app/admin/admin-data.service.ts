import { Injectable } from "@angular/core";
import { GeneralDataService } from "app/general-data.service";
import {
  RegionCountResponse,
  Region,
  SearchResponse,
  SortParameters,
  FilterParameters,
  SearchParameters,
  AdminPageMode,
} from "app/interfaces/admin_interfaces";

@Injectable()
export class AdminDataService {
  public GenericErrorMessage;
  generalDataService: GeneralDataService;
  constructor(private dataService: GeneralDataService) {
    this.generalDataService = dataService;
    this.GenericErrorMessage = dataService.GenericErrorMessage;
  }

  monthNames = [
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
  ];

  buildSortString(sortParameters: SortParameters): string {
    if (sortParameters.length == 0) return "";
    
    let serverSortParameters = [...sortParameters];
    //Expand name into last_name, middle_name, first_name
    var indexOfName = serverSortParameters.findIndex((sp) => sp.prop == "name");
    if (indexOfName >= 0) {
      var dir = serverSortParameters.find((sp) => sp.prop == "name").dir;
      var nameArray: SortParameters = [
        { prop: "last_name", dir: dir },
        { prop: "first_name", dir: dir },
        { prop: "middle_name", dir: dir },
      ];
      serverSortParameters.splice(indexOfName, 1, ...nameArray);
    }

    //Handle ordering
    var orderingString = "&ordering=";
    serverSortParameters.forEach((order) => {
      var orderName = order.prop;
      if (orderName === "created_date") orderName += "__date";
      if (order.dir === "desc") orderingString += "-";
      orderingString += `${orderName},`;
      //Remove trailing comma.
      if (serverSortParameters[serverSortParameters.length - 1] === order) {
        orderingString = orderingString.slice(0, -1);
      }
    });

    return orderingString;
  }

  buildFilterString(filterParameters: FilterParameters): string {
    return Object.keys(filterParameters)
      .filter(
        (x) =>
          filterParameters[x] !== null &&
          filterParameters[x].toString().trim().length !== 0
      )
      .map((key) => {
        var snakeCaseKey = key.replace(
          /[A-Z]/g,
          (letter) => `_${letter.toLowerCase()}`
        );

        return `${encodeURIComponent(snakeCaseKey)}=${encodeURIComponent(
          filterParameters[key].toString().trim()
        )}`;
      })
      .join("&");
  }

  buildQueryString(searchParameters: SearchParameters): string {
    //Clone our search parameters. 
    let searchParam = JSON.parse(JSON.stringify(searchParameters)) as  SearchParameters

    //Move date from search into createdDate. 
    var dateRegex = /([0123]?[0-9])-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-(\d{4})/ig;
    var match = searchParam.filterParameters.search.match(dateRegex);
    if (match != null && match.length === 1) {
      let targetDate = new Date(match[0].replace(/-/g," ")).toISOString();
      searchParam.filterParameters.createdDate = targetDate;
      if (searchParam.filterParameters.isArchived)
        searchParam.filterParameters.archivedDate = targetDate;
      searchParam.filterParameters.search = searchParam.filterParameters.search.replace(dateRegex,"").trim();
    }

    var filterString = this.buildFilterString(
      searchParam.filterParameters
    );
    var sortString = this.buildSortString(searchParam.sortParameters);
    return `?${filterString}${sortString}`;
  }

  buildDayMonthWordYearDateString(targetDate: Date): string {
    return `${new Date(targetDate).getDate()}-${this.monthNames[new Date(targetDate).getMonth()]}-${new Date(targetDate).getFullYear()}`;
  }

  buildTimeString(targetDate: Date): string {
    return new Date(targetDate).toLocaleTimeString();
  }

  async getData(searchParameters: SearchParameters) {
    var action = this.buildQueryString(searchParameters);
    const url = this.generalDataService.getApiUrl("responses/" + action);
    console.log(url);
    return (await this.generalDataService.loadJson(url)) as SearchResponse;
  }

  async getSearchResponse(
    searchParameters: SearchParameters
  ): Promise<SearchResponse> {
    var searchResponse = await this.getData(searchParameters);
    searchResponse.results = searchResponse.results.map((r) => ({
      ...r,
      created_date: this.buildDayMonthWordYearDateString(r.created_date as Date),
      archived_date: this.buildDayMonthWordYearDateString(r.archived_date as Date) + " " + this.buildTimeString(r.archived_date as Date),
      name: `${r.last_name}, ${r.first_name} ${r.middle_name || ""}`,
      hearing_location__name: r.hearing_location != null ? `${r.hearing_location.name}` : null,
      archived_by__name: r.archived_by !== null ? `${r.archived_by.last_name}, ${r.archived_by.first_name}` : null
    }));

    return searchResponse;
  }

  async getRegions(): Promise<Array<Region>> {
    const url = this.generalDataService.getApiUrl("regions/");
    return (await this.generalDataService.loadJson(url)) as Array<Region>;
  }

  async getCounts(): Promise<RegionCountResponse> {
    const url = this.generalDataService.getApiUrl("responses/counts/");
    return (await this.generalDataService.loadJson(url)) as RegionCountResponse;
  }

  async getPdf(targetPdfIds: Array<number>, mode: AdminPageMode) : Promise<BlobPart> {
    const url = this.generalDataService.getApiUrl("pdf/");
    try {
      return await this.generalDataService.executePostBlob(url, {
        id: [...targetPdfIds], mode: mode
      }) as BlobPart
    } 
    catch (error) {
      if (error.error) {
        var decodedString = String.fromCharCode.apply(null, new Uint8Array(error.error));
        return decodedString;
      }
      console.error(error);
      return error;
    }
  }

  async markFilesAsArchived(targetPdfIds) {
    const url = this.generalDataService.getApiUrl("archived/");
    return await this.generalDataService.executePostJson(url, {
      id: [...targetPdfIds]
    })
  }

  async deleteTicketResponse(id) : Promise<string> {
    const url = this.generalDataService.getApiUrl(`responses/${id}/`);
    try {
      return await this.generalDataService.delete(url)
    }
    catch (error) {
      if (error && error.status === 404)
        return "not found"
      return "error"
    }
  }

  isSuperUser() {
    return this.generalDataService.isSuperUser();
  }
}
