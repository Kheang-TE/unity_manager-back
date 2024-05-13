import coreDatamapper from './core.datamapper.js';

export default class listDatamapper extends coreDatamapper {
  constructor(tableName = 'list') {
    super();
    this.tableName = tableName;
  }
}
