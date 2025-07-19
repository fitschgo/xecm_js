# XECM

This nodejs library calls the Opentext Extended ECM REST API.
The API documentation is available on [OpenText Developer](https://developer.opentext.com/ce/products/extendedecm)
A detailed documentation of this package is available [on GitHub](https://github.com/fitschgo/xecm_js).
Our Homepage is: [xECM SuccessFactors Knowledge](https://www.xecm-successfactors.com/xecm-knowledge.html)

# Quick start

Install "xecm":

```bash
npm install xecm
```

## Start using the xecm package
```js
const xecm = require('xecm');
const https = require('https')
const http = require('http')
const fs = require('fs');
const path = require('path');

async function mainProg() {
    let cshost = 'http://otcs.phil.local';
    let dshost = 'http://otds.phil.local';
    let cspath = '/otcs/cs.exe';

    // get OTCSTicket with username and password
    let csapi = new xecm.CSRestAPI(xecm.LoginType.OTCS_TICKET, `${cshost}${cspath}`, 'myuser', 's#cret', true, xecm.LogType.INFO);  // use xecm.LogType.ERROR to reduce logging
    await csapi.doLogin();

    // get OTDSTicket with username and password
    //let csapi = new xecm.CSRestAPI(LoginType.OTDS_TICKET, dshost, 'myuser@partition', 's#cret', true, xecm.LogType.INFO);  // use xecm.LogType.ERROR to reduce logging
    //await csapi.doLogin();

    // get OTDS Bearer Token with client id and client secret
    //let csapi = new xecm.CSRestAPI(xecm.LoginType.OTDS_BEARER, dshost, 'oauth-user', 'gU5p8....4KZ', true, xecm.LogType.INFO);  // use xecm.LogType.ERROR to reduce logging
    //await csapi.doLogin();

    // ...

    let nodeId = 130480
    try {
        let res = csapi.node_get(`${cshost}${cspath}`, nodeId, ['id', 'name', 'type', 'type_name'], false, false, false);
        console.log(res);
        // {
        //   'properties': {'id': 130480, 'name': 'Bewerbung-Phil-Egger-2020.pdf', 'type': 144, 'type_name': 'Document'}, 
        //   'categories': [], 
        //   'permissions': {'owner': {}, 'group': {}, 'public': {}, 'custom': []}, 
        //   'classifications': []
        // }
    } catch(innerErr) {
      if (innerErr instanceof xecm.LoginTimeoutException) {
        console.error(`Ticket has been invalidated since last login (timeout) - do a re-login: ${innerErr}`)
      } else {
        console.error(`General Error: ${innerErr}`)
      }
    }
}

// run main program
mainProg();

```

## Available Logins: OTCSTicket, OTDSTicket or OTDS Bearer Token
```js
    // get OTCSTicket with username and password
    let csapi = new xecm.CSRestAPI(xecm.LoginType.OTCS_TICKET, `${cshost}${cspath}`, 'myuser', 's#cret', true, xecm.LogType.INFO);  // use xecm.LogType.ERROR to reduce logging
    await csapi.doLogin();

    // get OTDSTicket with username and password
    let csapi = new CSRestAPI(xecm.LoginType.OTDS_TICKET, dshost, 'myuser@partition', 's#cret', true, xecm.LogType.INFO);  // use xecm.LogType.ERROR to reduce logging
    await csapi.doLogin();

    // get OTDS Bearer Token with client id and client secret
    let csapi = new CSRestAPI(xecm.LoginType.OTDS_BEARER, dshost, 'oauth-user', 'gU5p8....4KZ', true, xecm.LogType.INFO);  // use xecm.LogType.ERROR to reduce logging
    await csapi.doLogin();
```

## Node Functions (folder, document, ...)
```js
    // get node information - min -> load only some fields
    let res = csapi.node_get(`${cshost}${cspath}`, nodeId, ['id', 'name', 'type', 'type_name'], false, false, false);

    // get node information - max -> load all fields, incl. categories, incl. permissions, incl. classifications
    let res = csapi.node_get(`${cshost}${cspath}`, nodeId, [], true, true, true);

    // get sub nodes - min
    let res = csapi.subnodes_get(`${cshost}${cspath}`, nodeId, ['id', 'name'], false, false, false, 1);  // page 1 contains 200 sub items

    // get sub nodes - load categories
    let res = csapi.subnodes_get(`${cshost}${cspath}`, nodeId, ['id', 'name'], true, false, false, 1);  // page 1 contains 20 sub items

    // get sub nodes - load permissions
    let res = csapi.subnodes_get(`${cshost}${cspath}`, nodeId, ['id', 'name'], false, true, false, 1);  // page 1 contains 20 sub items

    // get sub nodes - load classifications
    let res = csapi.subnodes_get(`${cshost}${cspath}`, nodeId, ['id', 'name'], false, false, true, 1);  // page 1 contains 10 sub items

    // filter subnodes
    let res = csapi.subnodes_filter(`${cshost}${cspath}`, 30622, 'OTHCM_WS_Employee_Categories', false, true);

    // search nodes
    let res = csapi.search(`${cshost}${cspath}`, 'Documents', 0, baseFolderId, 1);

    // get details of several nodes - max 250 entries
    let res = csapi.nodes_get_details(`${cshost}${cspath}`, [ 30724, 30728, 30729 ]);

    // create new node - min
    let res = csapi.node_create(`${cshost}${cspath}`, parentId, 0, 'test', 'test', {}, {} );

    // create new node - with multiple metadata names
    let res = csapi.node_create(`${cshost}${cspath}`, nodeId, 0, 'test', 'test', { 'en': 'test en', 'de': 'test de'}, { 'en': 'desc en', 'de': 'desc de'} );
    
    // update name and description of a node (folder, document, ...) - min
    let res = csapi.node_update(`${cshost}${cspath}`, nodeId, 0, 'test1', 'desc1', {}, {}, {});

    // move node and apply categories
    let cats = { '1279234_2': 'test' }
    let res = csapi.node_update(`${cshost}${cspath}`, nodeId, newDestId, '', '', {}, {}, cats);

    // delete a node
    let res = csapi.node_delete(`${cshost}${cspath}`, nodeId);
    
    // download a document into file system
    let res = csapi.node_download_file(`${cshost}${cspath}`, nodeId, '', '/home/fitsch/Downloads', 'test-download.pdf');

    // download a document as base64 string
    let res = csapi.node_download_bytes(`${cshost}${cspath}`, nodeId, '');
    // {'message', 'file_size', 'base64' }

    // upload a document from file system
    let res = csapi.node_upload_file(`${cshost}${cspath}`, nodeId, '/home/fitsch/Downloads', 'test-download.pdf', 'test-upload.pdf', { '30724_2': '2020-03-17' });

    // upload a document from byte array
    let barr = fs.readFileSync(path.join("/home/fitsch/Downloads/", "test-download5.pdf"));
    let res = csapi.node_upload_bytes(`${cshost}${cspath}`, nodeId, barr, 'test-upload.pdf', {'30724_2': '2020-03-17'});

    // covert a Content Server path to a Node ID
    let res = csapi.path_to_id(`${cshost}${cspath}`, 'Content Server Categories:SuccessFactors:OTHCM_WS_Employee_Categories:Personal Information');

    // get all volumes in Content Server
    let res = csapi.volumes_get(`${cshost}${cspath}`);
    // [
    // {
    //   'properties': 
    //   {
    //       'id': 2006, 
    //       'name': 'Content Server Categories'
    //   }
    // }, 
    // {
    //   'properties': 
    //   {
    //       'id': 2000, 
    //       'name': 'Enterprise'
    //   }
    // }, 
    // ...
    // ]

```

## Category Functions (Metadata)
```js
    // get node information and load categories
    let res = csapi.node_get(`${cshost}${cspath}`, nodeId, ['id', 'name'], true, false, false);

    // add category to node
    let res = csapi.node_category_add(`${cshost}${cspath}`, nodeId, { "category_id": 32133, "32133_2": "8000", "32133_39": ["test 1", "test 2"], "32133_33_1_34": "Org Unit 1", "32133_33_1_35": "Org Unit Desc 1", "32133_33_2_34": "Org Unit 2", "32133_33_2_35": "Org Unit Desc 2" } );

    // update category on a node
    let res = csapi.node_category_update(`${cshost}${cspath}`, nodeId, 32133, { "32133_2": "8000", "32133_39": ["test 1", "test 2"], "32133_33_1_34": "Org Unit 1", "32133_33_1_35": "Org Unit Desc 1", "32133_33_2_34": "Org Unit 2", "32133_33_2_35": "Org Unit Desc 2" } );
    
    // delete category from a node
    let res = csapi.node_category_delete(`${cshost}${cspath}`, nodeId, 32133);

    // read all category attributes - use i.e. path_to_id() to get cat_id
    let res = csapi.category_get_mappings(`${cshost}${cspath}`, cat_id);
    // {
    //   'main_name': 'Job Information', 
    //   'main_id': 32133, 
    //   'map_names': 
    //   {
    //       'Company Code': '32133_2', 
    //       'Company Code Description': '32133_3', 
    //       ...
    //   }, 
    //   'map_ids': 
    //   {
    //       '32133_2': 'Company Code', 
    //       '32133_3': 'Company Code Description', 
    //       ...
    //   }
    // }
    
    // get category information for a specific attribute
    let res = csapi.category_attribute_id_get(`${cshost}${cspath}`, 'Content Server Categories:SuccessFactors:OTHCM_WS_Employee_Categories:Personal Information', 'User ID');
    // {
    //   'category_id': 30643, 
    //   'category_name': 'Personal Information', 
    //   'attribute_key': '30643_26', 
    //   'attribute_name': 'User ID'
    // }
```

## Classification Functions
```js
    // get node information and load classifications
    let res = csapi.node_get(`${cshost}${cspath}`, nodeId, ['id', 'name'], false, false, true);

    // apply classifications to node
    let res = csapi.node_classifications_apply(`${cshost}${cspath}`, nodeId, false, [120571,120570]);
    
    // same function to remove classification 120570 from node
    let res = csapi.node_classifications_apply(`${cshost}${cspath}`, nodeId, false, [120571]);
```

## Permission Functions
```js
    // get node information and load permissions
    let res = csapi.node_get(`${cshost}${cspath}`, nodeId, ['id', 'name'], false, true, false);

    // apply owner permissions on node
    /*
    The allowable values for permissions are:
    "see"
    "see_contents"
    "modify"
    "edit_attributes"
    "add_items"
    "reserve"
    "add_major_version"
    "delete_versions"
    "delete"
    "edit_permissions"

    Apply the change to different levels:
    0 This Item
    1 Sub-Items
    2 This Item and Sub-Items
    3 This Item And Immediate Sub-Items
    */
    let res = csapi.node_permissions_owner_apply(`${cshost}${cspath}`, nodeId, { "permissions":["delete","delete_versions","edit_attributes","edit_permissions","modify","reserve","see","see_contents"], "right_id": 1000 });

    // delete owner permission from node
    let res = csapi.node_permissions_owner_delete(`${cshost}${cspath}`, nodeId);

    // apply group permissions on node
    let res = csapi.node_permissions_group_apply(`${cshost}${cspath}`, nodeId, {"permissions":["delete","delete_versions","edit_attributes","edit_permissions","modify","reserve","see","see_contents"], "right_id": 2001 });

    // delete group permission from node
    let res = csapi.node_permissions_group_delete(`${cshost}${cspath}`, nodeId);

    // apply public permissions on node
    let res = csapi.node_permissions_public_apply(`${cshost}${cspath}`, nodeId, {"permissions":["delete","delete_versions","edit_attributes","edit_permissions","modify","reserve","see","see_contents"] });

    // delete public permission from node
    let res = csapi.node_permissions_public_delete(`${cshost}${cspath}`, nodeId);

    // apply a new custom permissions on node
    let res = csapi.node_permissions_custom_apply(`${cshost}${cspath}`, nodeId, [{"permissions":["see","see_contents"], "right_id": 1001 }]);

    // update an existing custom permissions on node
    let res = csapi.node_permissions_custom_update(`${cshost}${cspath}`, nodeId, 2001, {"permissions":["delete","delete_versions","edit_attributes","edit_permissions","modify","reserve","see","see_contents"] });

    // delete a custom permissions from node
    let res = csapi.node_permissions_custom_delete(`${cshost}${cspath}`, nodeId, 1001);
```

## Smart Document Types Functions
```js
    // get all smart document types
    let res = csapi.smartdoctypes_get_all(`${cshost}${cspath}`);
    for (let i=0; i<res.length; i++) {
        let smartdoctype = res[i];
        console.log(`${smartdoctype['workspace_template_names']} - ${smartdoctype['dataId']} - ${smartdoctype['name']} --> ${smartdoctype['classification_id']} - ${smartdoctype['classification_name']}`);
    }

    // get rules of a smart document type
    smartDocTypeId = smartdoctype['dataId'];
    let res = csapi.smartdoctypes_rules_get(`${cshost}${cspath}`, smartDocTypeId);
    for (let i=0; i<res.length; i++) {
        let smartdoctype = res[i];
        console.log(`${smartdoctype['template_name']} (${smartdoctype['template_id']}) - ${smartdoctype['smartdocumenttype_id']} - RuleID: ${smartdoctype['rule_id']} / DocGen: ${smartdoctype['document_generation']} --> Classification: ${smartdoctype['classification_id']} --> Location: ${smartdoctype['location']}`);
    }

    // get rule detail
    ruleId = smartdoctype['rule_id'];
    let res = csapi.smartdoctype_rule_detail_get(`${cshost}${cspath}`, ruleId);
    for (let i=0; i<res.length; i++) {
        let rule_tabl = res[i];
        console.log(`tab: {rule_tab['bot_key']} - data: {rule_tab['data']}`);
    }

    // create smart document type under "Smart Document Types" root folder 6004 (id is different per system) -> see get_volumes() function
    let res = csapi.smartdoctype_add(`${cshost}${cspath}`, 6004, categoryId, 'smart doc test');

    // add workspace template to rule
    let res = csapi.smartdoctype_workspacetemplate_add(`${cshost}${cspath}`, smartDocTypeId, classificationId, templateId);
    // {
    //   'is_othcm_template': true, 
    //   'ok': true, 
    //   'rule_id': 11, 
    //   'statusCode': 200
    // }

    // add workspace template to rule -> get locationId with path_to_id() function
    let location = csapi.path_to_id(`${cshost}${cspath}`, 'Content Server Document Templates:SuccessFactors:Employee CHE:01 Entry Documents:110 Recruiting / Application');
    // {'id': 120603, 'name': '110 Recruiting / Application'}
    let locationId = location['id'];
    let res = csapi.smartdoctype_rule_context_save(`${cshost}${cspath}`, ruleId, categoryId, locationId, 'update');
    // {
    //   'ok': true, 
    //   'statusCode': 200, 
    //   'updatedAttributeIds': [2], 
    //   'updatedAttributeNames': ['Date of Origin']
    // }

    // add 'mandatory' tab in rule
    let res = csapi.smartdoctype_rule_mandatory_save(`${cshost}${cspath}`, ruleId, true, 'add');

    // update 'mandatory' tab in rule
    let res = csapi.smartdoctype_rule_mandatory_save(`${cshost}${cspath}`, ruleId, false, 'update');

    // delete 'mandatory' tab in rule
    let res = csapi.smartdoctype_rule_mandatory_delete(`${cshost}${cspath}`, ruleId);

    // add 'document expiration' tab in rule
    let res = csapi.smartdoctype_rule_documentexpiration_save(`${cshost}${cspath}`, ruleId, true, 2, 0, 6, 'add');

    // update 'document expiration' tab in rule
    let res = csapi.smartdoctype_rule_documentexpiration_save(`${cshost}${cspath}`, ruleId, false, 2, 0, 4, 'update');

    // delete 'document expiration' tab in rule
    let res = csapi.smartdoctype_rule_documentexpiration_delete(`${cshost}${cspath}`, ruleId);

    // add 'document generation' tab in rule
    let res = csapi.smartdoctype_rule_generatedocument_save(`${cshost}${cspath}`, ruleId, true, false, 'add');

    // update 'document generation' tab in rule
    let res = csapi.smartdoctype_rule_generatedocument_save(`${cshost}${cspath}`, ruleId, false, false, 'update');

    // delete 'document generation' tab in rule
    let res = csapi.smartdoctype_rule_generatedocument_delete(`${cshost}${cspath}`, ruleId);

    // add 'allow upload' tab in rule
    let res = csapi.smartdoctype_rule_allowupload_save(`${cshost}${cspath}`, ruleId, [2001], 'add');

    // update 'allow upload' tab in rule
    let res = csapi.smartdoctype_rule_allowupload_save(`${cshost}${cspath}`, ruleId, [2001,120593], 'update');

    // delete 'allow upload' tab in rule
    let res = csapi.smartdoctype_rule_allowupload_delete(`${cshost}${cspath}`, ruleId);

    // add 'upload approval' tab in rule
    let res = csapi.smartdoctype_rule_uploadapproval_save(`${cshost}${cspath}`, ruleId, true, workflowMapId, [{'wfrole': 'Approver', 'member': 2001 }], 'add');

    // update 'upload approval tab in rule
    let res = csapi.smartdoctype_rule_uploadapproval_save(`${cshost}${cspath}`, ruleId, true, workflowMapId, [{'wfrole': 'Approver', 'member': 120593 }], 'update');

    // delete 'upload approval' tab in rule
    let res = csapi.smartdoctype_rule_uploadapproval_delete(`${cshost}${cspath}`, ruleId);

    // add 'reminder' tab in rule
    // be sure that user/oauth client has enough permissions: otherwise you will get an exception: check volume Reminders:Successfactors Client or Standard Client - Failed to add Bot "reminder" on template.
    let res = csapi.smartdoctype_rule_reminder_save(`${cshost}${cspath}`, 11, true, 'add');

    // update 'reminder' tab in rule
    let res = csapi.smartdoctype_rule_reminder_save(`${cshost}${cspath}`, 11, true, 'update');

    // delete 'reminder' tab in rule
    let res = csapi.smartdoctype_rule_reminder_delete(`${cshost}${cspath}`, ruleId);

    // add 'review upload' tab in rule
    let res = csapi.smartdoctype_rule_reviewuploads_save(`${cshost}${cspath}`, 11, true, 'Test Review', [2001], 'add');

    // update 'review upload' tab in rule
    let res = csapi.smartdoctype_rule_reviewuploads_save(`${cshost}${cspath}`, 11, false, 'Test Review', [2001], 'update');

    // delete 'review upload' tab in rule
    let res = csapi.smartdoctype_rule_reviewuploads_delete(`${cshost}${cspath}`, ruleId);

    // add 'allow delete' tab in rule
    let res = csapi.smartdoctype_rule_allowdelete_save(`${cshost}${cspath}`, 11, [2001], 'add');

    // update 'allow delete' tab in rule
    let res = csapi.smartdoctype_rule_allowdelete_save(`${cshost}${cspath}`, 11, [2001,120593], 'update');

    // delete 'allow delete' tab in rule
    let res = csapi.smartdoctype_rule_allowdelete_delete(`${cshost}${cspath}`, 11);

    // add 'delete approval' tab in rule
    let res = csapi.smartdoctype_rule_deletewithapproval_save(`${cshost}${cspath}`, ruleId, true, workflowMapId, [{'wfrole': 'Approver', 'member': 2001 }], 'add');

    // update 'delete approval' tab in rule
    let res = csapi.smartdoctype_rule_deletewithapproval_save(`${cshost}${cspath}`, ruleId, true, workflowMapId, [{'wfrole': 'Approver', 'member': 120593 }], 'update');

    // delete 'delete approval' tab in rule
    let res = csapi.smartdoctype_rule_deletewithapproval_delete(`${cshost}${cspath}`, ruleId);
```

## Business Workspace Functions
```js
    // get business workspace node id by business object type and business object id
    let res = csapi.businessworkspace_search(`${cshost}${cspath}`, 'SuccessFactors', 'sfsf:user', 'Z70080539', 1);

    // get customized smart document types for business workspace
    // bws_id from businessworkspace_search()
    let res = csapi.businessworkspace_smartdoctypes_get(`${cshost}${cspath}`, bws_id);
    // [{'classification_id': 120571, 'classification_name': 'Application Documents', 'classification_description': '', 'category_id': 6002, 'location': '122061:122063', 'document_generation': 0, 'required': 0, 'template_id': 120576}, ...]
    
    // get category definition for smart document type to be used for document upload into business workspace
    // bws_id from businessworkspace_search()
    // cat_id from businessworkspace_smartdoctypes_get()
    let res = csapi.businessworkspace_categorydefinition_for_upload_get(`${cshost}${cspath}`, bws_id, cat_id);

    // upload file using smart document type into business workspace
    let res = csapi.businessworkspace_hr_upload_file(`${cshost}${cspath}`, bws_id, '/home/fitsch/Downloads', 'test-download.pdf', 'application.pdf', class_dict['classification_id'], cat_id, cat_dict);
    
    //### ########################## #####
    //### snippet for upload process #####
    //### ########################## #####
    let res = await csapi.businessworkspace_search(`${cshost}${cspath}`, 'SuccessFactors', 'sfsf:user', 'Z70080539', 1);

    let bws_id = -1;
    let class_name = 'Application Documents';
    let class_dict = {};
    let cat_id = -1;
    let cat_attr_date_of_origin = '';
    let cat_dict = {};
    let date_of_origin = new Date(2020, 4, 17);
    // res = {'results': [{'id': 122051, 'name': 'Employee Z70080539 Phil Egger', 'parent_id': 30648}, ... ], 'page_total': 1}
    if (res && res['results'] && res['results'].length > 0) {
      bws_id = res['results'][0]['id'];
    }

    if (bws_id > 0) {
      res = await csapi.businessworkspace_smartdoctypes_get(`${cshost}${cspath}`, bws_id);
      // res = [{'classification_id': 120571, 'classification_name': 'Application Documents', 'classification_description': '', 'category_id': 6002, 'location': '122061:122063', 'document_generation': 0, 'required': 0, 'template_id': 120576}, ... ]
      if (res) {
        for (let i=0; i<res.length; i++) {
          let class_def = res[i];
          if (class_def['classification_name'] === class_name) {
            class_dict = class_def;
            break;
          }
        }
      }

      if (class_dict) {
        // class_dict = {'classification_id': 120571, 'classification_name': 'Application Documents', 'classification_description': '', 'category_id': 6002, 'location': '122061:122063', 'document_generation': 0, 'required': 0, 'template_id': 120576}
        res = await csapi.businessworkspace_categorydefinition_for_upload_get(`${cshost}${cspath}`, bws_id, class_dict['category_id']);
        // res = [{'data': {'category_id': 6002, '6002_2': None}, 'options': {}, 'form': {}, 'schema': {'properties': {'category_id': {'readonly': False, 'required': False, 'title': 'Document Type Details', 'type': 'integer'}, '6002_2': {'readonly': False, 'required': False, 'title': 'Date of Origin', 'type': 'date'}}, 'type': 'object'}}]
        if (res && res.length > 0) {
          if (res[0]['schema'] && res[0]['schema']['properties']) {
            // res[0]['schema']['properties'] = {'category_id': {'readonly': False, 'required': False, 'title': 'Document Type Details', 'type': 'integer'}, '6002_2': {'readonly': False, 'required': False, 'title': 'Date of Origin', 'type': 'date'}}
            cat_id = class_dict['category_id'];
            for (let p in res[0]['schema']['properties']) {
              if (`${p}`.includes(`${cat_id}`) && res[0]['schema']['properties'][p]['type'] === 'date' && res[0]['schema']['properties'][p]['title'].includes('Origin')) {
                cat_attr_date_of_origin = p;
                break;
              }
            }
          }
        }

        if (cat_id > 0 && cat_attr_date_of_origin) {
          cat_dict = { };
          cat_dict[cat_attr_date_of_origin] = date_of_origin.toISOString();

        } else {
          console.log(`Date Of Origin not found in Category ${class_dict['category_id']} for Workspace ${bws_id}`);
        }

        try {
          res = await csapi.businessworkspace_hr_upload_file(`${cshost}${cspath}`, bws_id, '/home/fitsch/Downloads', 'test-download.pdf', 'application.pdf', class_dict['classification_id'], cat_id, cat_dict);
          if (res > 0) {
            console.log(`File successfully uploaded - ${res}`);
          } else {
            throw new Error(`Invalid Node ID returned: ${res}`);
          }
        } catch(innerErr) {
            console.error(`File failed to upload ${innerErr}`);
        }
        
      } else {
          console.error(`Classification Definition not found for ${class_name} in Workspace ${bws_id}`);
      }
    }
    console.log(bws_id);
    console.log(class_dict);
    console.log(class_dict['classification_id']);
    console.log(cat_id);
    console.log(cat_attr_date_of_origin);
    console.log(cat_dict);
    console.log(date_of_origin);

```

## WebReport Functions
```js
    // call web report by nickname using parameters
    let res = csapi.webreport_nickname_call(`${cshost}${cspath}`, 'WR_API_Test', {'p_name': 'name', 'p_desc': 'description'});

    // call web report by node id using parameters
    let res = csapi.webreport_nodeid_call(`${cshost}${cspath}`, wr_id, {'p_name': 'name', 'p_desc': 'description'});
```

## Server Information Functions
```js
    // ping Content Server
    let res = csapi.ping(`${cshost}${cspath}`);

    // get server info (version, metadata languages, ...)
    let res = csapi.server_info(`${cshost}${cspath}`);
    console.log(`Version: ${res['server']['version']}`);
    console.log('Metadata Languages:');
    for (let i=0; i<res['server']['metadata_languages'].length; i++) {
        let lang = res['server']['metadata_languages'][i];
        console.log(`${lang['language_code']} - ${lang['display_name']}`);
    }
```

## Basic API Functions - in case that something is not available in this class
```js
    // GET API Call
    async function mainProg() {
        let csapi = new xecm.CSRestAPI(xecm.LoginType.OTCS_TICKET, "http://otcs1.phil.local/otcs/cs.exe", "otadmin@otds.admin", "pdfT78#ReDoAkte_", false, xecm.LogType.DEBUG);
        await csapi.doLogin();

        let req_headers = {
            'User-Agent': csapi._userAgent,
            'Content-Type': 'application/json'
        };
        req_headers = csapi._addAuthHeader(req_headers);

        let options = {
            hostname: 'otcs1.phil.local',
            port: 443,  // or 80
            path: '/otcs/cs.exe/api/v1/nodes/2000',
            method: 'GET',
            headers: req_headers
        };

        //let res = await csapi.doCallHttp(null, options);  // if port 80
        let res = await csapi.doCallHttps(null, options);

        if (res['statusCode'] === 200) {
            const jres = JSON.parse(res['body'].toString("utf8"));
            // evaluate result here
            console.log(jres);
        } else if(res['statusCode'] === 401) {
            throw new xecm.LoginTimeoutException(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
        } else {
            throw new Error(`statusCode: ${res['statusCode']}: ${res['body'].toString('utf8')}`);
        }
    }
    mainProg();
```

# Disclaimer

Copyright © 2025 by Philipp Egger, All Rights Reserved. The copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.