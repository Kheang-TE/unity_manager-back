import coreDatamapper from './core.datamapper.js';

export default class listDatamapper extends coreDatamapper {
  constructor(tableName = 'card') {
    super();
    this.tableName = tableName;
  }
}
